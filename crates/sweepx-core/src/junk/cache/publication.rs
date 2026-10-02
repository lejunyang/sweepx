//! Borrowed preparation for optional candidate-cache publication, separate from live evidence.

use super::StoredJunkCandidate;
use super::grouping::{
    DEFAULT_GROUPING_BYTES, GroupingBudget, RootGroups, RootScope, group_native,
};
use crate::junk::candidate::JunkCandidate;
use crate::junk::git::native_path;
use std::collections::{BTreeMap, btree_map::Entry};
use std::io;
use std::path::PathBuf;
use sweepx_model::DirectoryAggregate;
use sweepx_platform::CancellationToken;

/// One bounded, borrowed candidate-publication view for the caller's original root scope.
///
/// Candidate locators are decoded once during preparation, never from display paths. The deepest
/// original root owns each candidate; equal root spellings belong to their final input ordinal.
/// Foreign candidates are omitted. Missing or invalid native evidence rejects the whole optional
/// view, so a caller must skip cache publication on error rather than publish a complete empty
/// record. Live scan results and their coverage remain independent of this optimization.
///
/// The root/bucket capacities and borrowed aggregate index share an 8 MiB auxiliary estimate,
/// including spare capacity, an initial nonempty-map node allowance and per-identity ordered-map
/// estimates. Borrowed scan payloads and per-root owned projections are separate allocations; this
/// is not an RSS limit. No classification, native reopening, cache validation, activity inference or
/// execution permission is created here.
pub struct CandidateCacheGroups<'a> {
    scope: RootScope<'a>,
    candidates: RootGroups<&'a JunkCandidate>,
    aggregates: BTreeMap<&'a str, &'a DirectoryAggregate>,
}

impl<'a> CandidateCacheGroups<'a> {
    /// Prepares optional publication groups and a first-match aggregate index once.
    ///
    /// Roots must retain their original absolute spellings and fit the native path bound. This
    /// method does not canonicalize them or consult the filesystem. Every candidate, including a
    /// foreign one, must carry supported source-native evidence. Aggregate identity duplicates
    /// retain the first supplied row, matching the prior linear `find` behavior.
    ///
    /// Cancellation returns `Interrupted`; invalid roots return `InvalidInput`. Missing native
    /// evidence or exhausted auxiliary resources returns an error for the entire optional view.
    /// On any error, skip cache writing rather than replace prior cached facts with an empty set.
    pub fn prepare(
        roots: &'a [PathBuf],
        candidates: &'a [JunkCandidate],
        aggregates: &'a [DirectoryAggregate],
        cancel: &CancellationToken,
    ) -> io::Result<Self> {
        Self::prepare_with_budget(
            roots,
            candidates,
            aggregates,
            cancel,
            DEFAULT_GROUPING_BYTES,
        )
    }

    fn prepare_with_budget(
        roots: &'a [PathBuf],
        candidates: &'a [JunkCandidate],
        aggregates: &'a [DirectoryAggregate],
        cancel: &CancellationToken,
        bytes: usize,
    ) -> io::Result<Self> {
        check_cancel(cancel)?;
        for root in roots {
            check_cancel(cancel)?;
            if !root.is_absolute() || root.as_os_str().as_encoded_bytes().len() > 64 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "candidate-cache root has an unsupported native spelling",
                ));
            }
        }
        let mut budget = GroupingBudget::new(bytes);
        let scope = RootScope::new(roots, &mut budget).ok_or_else(|| preparation_error(cancel))?;
        let candidates = group_native(
            &scope,
            candidates.iter(),
            |candidate| {
                candidate
                    .source_entry
                    .as_ref()
                    .and_then(native_path)
                    .filter(|path| {
                        path.is_absolute() && path.as_os_str().as_encoded_bytes().len() <= 64 * 1024
                    })
            },
            None,
            &mut budget,
            cancel,
        )
        .ok_or_else(|| preparation_error(cancel))?;
        let aggregates = aggregate_index(aggregates, &mut budget, cancel)?;
        check_cancel(cancel)?;
        Ok(Self {
            scope,
            candidates,
            aggregates,
        })
    }

    /// Copies only the borrowed candidates owned by one original root, with matching scan facts.
    ///
    /// Calls should project and publish one root at a time, then release that owned projection.
    /// Each row checks cancellation before cloning; an interrupted projection returns no partial
    /// vector. Aggregate absence remains `None`, never fabricated complete or zero statistics.
    /// Transient interpretation is excluded by [`StoredJunkCandidate::from_candidate`].
    ///
    /// Out-of-range and earlier duplicate-root ordinals return `InvalidInput`; callers must publish
    /// only the final representative of duplicate roots. Errors never authorize a complete empty
    /// replacement, reopen a native path or grant an execution permission.
    pub fn project_root(
        &self,
        index: usize,
        cancel: &CancellationToken,
    ) -> io::Result<Vec<StoredJunkCandidate>> {
        check_cancel(cancel)?;
        if index >= self.scope.len() || !self.scope.is_representative(index) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "candidate-cache root is outside the scope or is an earlier duplicate",
            ));
        }
        let candidates = self.candidates.get(index);
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(candidates.len())
            .map_err(|_| io::Error::other("candidate-cache projection allocation failed"))?;
        for candidate in candidates {
            check_cancel(cancel)?;
            let mut stored = StoredJunkCandidate::from_candidate(candidate);
            stored.aggregate = self
                .aggregates
                .get(candidate.entry_id.as_str())
                .map(|aggregate| (**aggregate).clone());
            projected.push(stored);
        }
        check_cancel(cancel)?;
        Ok(projected)
    }
}

fn aggregate_index<'a>(
    aggregates: &'a [DirectoryAggregate],
    budget: &mut GroupingBudget,
    cancel: &CancellationToken,
) -> io::Result<BTreeMap<&'a str, &'a DirectoryAggregate>> {
    let mut index = BTreeMap::new();
    for aggregate in aggregates {
        check_cancel(cancel)?;
        let first_node = index.is_empty();
        if let Entry::Vacant(entry) = index.entry(aggregate.directory_identity.as_str()) {
            // A first insertion allocates an entire leaf even for one borrowed pair. Ordered
            // maps expose no capacity API: precharge a nonempty-map allowance, then the amortized
            // per-identity estimate. Duplicate identities allocate nothing and keep the first row.
            if (first_node && !budget.charge(1024)) || !budget.charge(128) {
                return Err(io::Error::other(
                    "candidate-cache aggregate index exceeds budget",
                ));
            }
            entry.insert(aggregate);
        }
    }
    check_cancel(cancel)?;
    Ok(index)
}

fn check_cancel(cancel: &CancellationToken) -> io::Result<()> {
    if cancel.is_cancelled() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "candidate-cache publication preparation cancelled",
        ))
    } else {
        Ok(())
    }
}

fn preparation_error(cancel: &CancellationToken) -> io::Error {
    check_cancel(cancel).err().unwrap_or_else(|| {
        io::Error::other("candidate-cache grouping lacks native evidence or exceeds budget")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use sweepx_model::{
        ArithmeticState, Coverage, CoverageState, DecimalU128, EvidenceValue, FieldProvenance,
        ReasonCode, ScanEntryId, ScanId,
    };

    fn aggregate(identity: &str, revision: u128) -> DirectoryAggregate {
        // Report-only aggregate values exercise indexing, never fabricate a native locator.
        DirectoryAggregate {
            scan_id: ScanId::new("aggregate-index-fixture"),
            directory_identity: identity.into(),
            revision: DecimalU128::new(revision),
            apparent_logical_bytes: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            unique_logical_bytes: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            filesystem_reported_allocated_bytes: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            potentially_reclaimable_bytes: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            direct_child_count: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            recursive_entry_count: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            coverage: Coverage {
                state: CoverageState::Incomplete,
                complete: false,
                incomplete_reasons: vec![ReasonCode::Unknown],
                details_lost: false,
                provenance: FieldProvenance::Unknown {
                    reason: ReasonCode::Unknown,
                },
            },
            arithmetic_state: ArithmeticState::Unknown,
        }
    }

    #[test]
    fn duplicate_aggregate_identity_keeps_first_without_charging_a_second_node() {
        let cancel = CancellationToken::new();
        let aggregates = [aggregate("same", 1), aggregate("same", 2)];
        let mut one_budget = GroupingBudget::new(2048);
        let first = aggregate_index(&aggregates[..1], &mut one_budget, &cancel).unwrap();
        assert!(std::ptr::eq(first["same"], &aggregates[0]));
        // The one-row control observes the allowance needed independently of the node constant.
        let mut duplicate_budget = GroupingBudget::new(one_budget.used_bytes());
        let duplicate = aggregate_index(&aggregates, &mut duplicate_budget, &cancel).unwrap();
        assert_eq!(duplicate.len(), 1);
        assert!(std::ptr::eq(duplicate["same"], &aggregates[0]));
        assert_eq!(duplicate_budget.used_bytes(), one_budget.used_bytes());
    }

    #[test]
    fn empty_views_do_not_need_auxiliary_allocation_but_nonempty_roots_and_indexes_do() {
        let cancel = CancellationToken::new();
        let empty = CandidateCacheGroups::prepare_with_budget(&[], &[], &[], &cancel, 0).unwrap();
        assert_eq!(
            empty.project_root(0, &cancel).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let roots = [PathBuf::from("/publication-fixture")];
        assert!(CandidateCacheGroups::prepare_with_budget(&roots, &[], &[], &cancel, 0).is_err());
        let aggregates = [aggregate("one", 1)];
        assert!(
            CandidateCacheGroups::prepare_with_budget(&[], &[], &aggregates, &cancel, 1).is_err()
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            matches!(CandidateCacheGroups::prepare(&[], &[], &[], &cancelled),
            Err(error) if error.kind() == io::ErrorKind::Interrupted)
        );
        let roots = [PathBuf::from("relative")];
        assert!(
            matches!(CandidateCacheGroups::prepare(&roots, &[], &[], &cancel),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn missing_native_source_rejects_optional_publication_instead_of_an_empty_root() {
        let candidate = StoredJunkCandidate {
            path: "/publication-fixture/invented-display".into(),
            rule_id: "fixture".into(),
            risk: "report-only".into(),
            reclaimable: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            evidence: String::new(),
            source_reviewed_at: String::new(),
            references: Vec::new(),
            entry_id: ScanEntryId::for_scan_ordinal(&ScanId::new("missing-source"), 1).unwrap(),
            ancestor_ids: BTreeSet::new(),
            size_is_logical: true,
            source_entry: None,
            git_scan_facts: None,
            aggregate: None,
        }
        .into_candidate();
        let roots = [PathBuf::from("/publication-fixture")];
        assert!(
            CandidateCacheGroups::prepare(&roots, &[candidate], &[], &CancellationToken::new())
                .is_err()
        );
    }
}
