//! Optional cache work stays on the session worker. Historical rows never become current by replay.

use super::*;
use crate::junk::cache::{
    CacheReader, StoredJunkCandidate, StoredJunkRoot,
    grouping::{
        DEFAULT_GROUPING_BYTES, GroupingBudget, RootGroups, RootScope, group_listings,
        group_native, group_sources,
    },
    provider::SubtreeCacheProvider,
};
use sweepx_model::{
    ArithmeticState, ByteValue, CountValue, Coverage, CoverageState, DecimalU128, FieldProvenance,
    ReasonCode,
};

/// A single root can project directly and stop at its optional wire limit. Only multiple roots
/// need a shared partition; unavailable views must never be treated as successfully empty facts.
enum ListingPublication<'a> {
    SingleRoot,
    Grouped(RootGroups<(&'a String, &'a sweepx_scanner::DirListing)>),
    Unavailable,
}

impl Worker {
    pub(super) fn restore_history(
        &mut self,
        reader: &mut CacheReader,
        service: &JunkService,
        rules_digest: [u8; 32],
        job: &Job,
        writer: &mut Writer,
    ) -> Result<(), JunkSessionFailure> {
        let platform_rules = if self.request.include_platform_rules {
            super::super::platform::load_platform_junk_rules().unwrap_or_default()
        } else {
            Vec::new()
        };
        for record in reader
            .historical_roots(&self.scan_roots)
            .into_iter()
            .flatten()
        {
            for mut stored in record.into_candidates() {
                if job.cancel.is_cancelled() {
                    return Ok(());
                }
                if !service.rules.iter().any(|rule| rule.id == stored.rule_id)
                    && !platform_rules.iter().any(|rule| rule.id == stored.rule_id)
                {
                    continue;
                }
                let Some(entry) = &stored.source_entry else {
                    continue;
                };
                let Some(path) = native_path(entry) else {
                    continue;
                };
                let Some(root) = native_root_path(entry) else {
                    continue;
                };
                if !self.scan_roots.contains(&root) || !path.starts_with(&root) {
                    continue;
                }
                let aggregate = historical_aggregate(&stored, entry);
                // Show only the native locator's lossless presentation, never a cached display
                // spelling that disagrees with it. No native action is authorized here.
                stored.path = path.to_string_lossy().into_owned();
                let mut candidate = stored.into_candidate();
                candidate.project_format = service
                    .project_rules()
                    .iter()
                    .find(|rule| rule.id == candidate.rule_id)
                    .and_then(|rule| rule.content_format)
                    .map(super::super::format::ProjectFormatEvidence::not_checked);
                candidate.reset_project_format_interpretation();
                candidate.blockers.push("historical_cache".into());
                let Some(key) = candidate_key(&candidate, &path) else {
                    continue;
                };
                if self.presentations.contains(&key) {
                    continue;
                }
                let row = Arc::new(JunkSessionCandidate {
                    candidate,
                    facts: JunkSessionFacts::Directory(Box::new(aggregate)),
                });
                if row
                    .cost()
                    .saturating_add(std::mem::size_of::<JunkSessionEvent>())
                    .saturating_add(256)
                    > self.request.limits.max_event_bytes
                {
                    continue;
                }
                if let Err(failure) = self.presentations.send_candidate(
                    writer,
                    self.request.limits,
                    key,
                    JunkSessionCandidateState::Historical,
                    rules_digest,
                    row,
                ) {
                    if failure.code == "resource_limit" {
                        // Optional preview omission is not a fresh traversal coverage gap. Its
                        // native scope index has a separate bound from retained scan payloads.
                        return Ok(());
                    }
                    return Err(failure);
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn store_cache(
        &self,
        directory: &Path,
        cursor: crate::FsEventId,
        provider: &mut SubtreeCacheProvider,
        scanned: &sweepx_scanner::ClassifiedScan,
        pending: &Rows,
        service: &JunkService,
        platform: &PlatformJunkSetup,
        job: &Job,
        partial: bool,
        writer: &mut Writer,
    ) -> Result<(), JunkSessionFailure> {
        let context = service
            .with_platform(&platform.rules, &platform.evidence)
            .classification_context_digest();
        // Complete local observations replace only selected subtrees. The provider retains
        // siblings only with complete history and the original root binding; candidate rows
        // become historical previews because shallow ancestor totals are not recomputed.
        let selected = job
            .selected
            .as_ref()
            .map(|keys| {
                keys.iter()
                    .map(|key| {
                        self.current
                            .get(key)
                            .and_then(|row| row.observed_native_path())
                            .ok_or_else(|| {
                                JunkSessionFailure::new(
                                    "refresh_binding_unavailable",
                                    "selected cache path unavailable",
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        if selected.is_some() && partial {
            return Ok(());
        }
        if scanned.observed_roots.is_empty() {
            return Ok(());
        }
        // Publication is optional. These views borrow bounded scan facts and charge spare Vec
        // capacity independently; allocation pressure never weakens live classification.
        let mut budget = GroupingBudget::new(DEFAULT_GROUPING_BYTES);
        let Some(scope) = RootScope::new(&self.scan_roots, &mut budget) else {
            cache_grouping_warning(writer, &job.cancel)?;
            return Ok(());
        };
        let Some(source_roots) =
            group_sources(&scope, &scanned.observed_roots, &mut budget, &job.cancel)
        else {
            cache_grouping_warning(writer, &job.cancel)?;
            return Ok(());
        };
        if source_roots.is_empty() {
            return Ok(());
        }
        let need_candidates = selected.is_some() || (!partial && context.is_some());
        let candidates = if need_candidates {
            group_candidates(
                &scope,
                pending,
                selected.as_deref(),
                &mut budget,
                &job.cancel,
            )
        } else {
            None
        };
        let listings = if scope.len() == 1 {
            ListingPublication::SingleRoot
        } else {
            match group_listings(
                &scope,
                &scanned.covered_paths,
                &scanned.dir_listings,
                &mut budget,
                &job.cancel,
            ) {
                Some(groups) => ListingPublication::Grouped(groups),
                None => ListingPublication::Unavailable,
            }
        };
        if (need_candidates && candidates.is_none())
            || matches!(&listings, ListingPublication::Unavailable)
        {
            cache_grouping_warning(writer, &job.cancel)?;
        }
        debug_assert!(budget.used_bytes() <= DEFAULT_GROUPING_BYTES);
        for (ordinal, root) in self.scan_roots.iter().enumerate() {
            if job.cancel.is_cancelled() {
                break;
            }
            let Some(source_root) = source_roots.get(ordinal).first() else {
                continue;
            };
            if let Some(paths) = &selected {
                // Never merge an empty/truncated candidate projection as a complete fragment.
                // Either shared view failing leaves the original preview/index generation intact.
                let Some(candidates) = &candidates else {
                    continue;
                };
                if matches!(&listings, ListingPublication::Unavailable) {
                    continue;
                }
                let Some(stored) = stored_candidates(candidates.get(ordinal), &job.cancel) else {
                    continue;
                };
                let result = match &listings {
                    ListingPublication::SingleRoot => provider.store_observed_fragment(
                        source_root,
                        &self.scan_roots,
                        cursor,
                        paths,
                        &scanned.covered_paths,
                        &scanned.dir_listings,
                        stored,
                    ),
                    ListingPublication::Grouped(listings) => provider
                        .store_observed_fragment_owned(
                            source_root,
                            &self.scan_roots,
                            cursor,
                            paths,
                            &scanned.covered_paths,
                            listings.get(ordinal).iter().copied(),
                            stored,
                        ),
                    ListingPublication::Unavailable => continue,
                };
                if let Err(error) = result {
                    writer.send(JunkSessionEventKind::CacheWarning(JunkSessionFailure::new(
                        "cache_fragment_write_failed",
                        error.to_string(),
                    )))?;
                }
                continue;
            }
            if !partial
                && root
                    .to_str()
                    .is_some_and(|path| scanned.covered_paths.get(path) == Some(&true))
                && let Some(context) = context
                && let Some(candidates) = &candidates
            {
                let Some(stored) = stored_candidates(candidates.get(ordinal), &job.cancel) else {
                    continue;
                };
                let result = StoredJunkRoot::capture_with_rule_bytes(
                    root,
                    stored,
                    cursor,
                    context,
                    &self.request.project_rule_bytes,
                    super::super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
                )
                .and_then(|mut record| {
                    if !record.matches_observed_root(source_root) {
                        return Err(std::io::Error::other("cache root changed after traversal"));
                    }
                    record.bind_scope(&self.scan_roots);
                    if job.cancel.is_cancelled() {
                        return Ok(());
                    }
                    crate::junk::cache::write(directory, &record)
                });
                if let Err(error) = result {
                    writer.send(JunkSessionEventKind::CacheWarning(JunkSessionFailure::new(
                        "cache_write_failed",
                        error.to_string(),
                    )))?;
                }
            }
            if !root
                .to_str()
                .is_some_and(|path| scanned.covered_paths.contains_key(path))
            {
                continue;
            }
            // Cancellation may arrive during candidate capture in this same root. Avoid
            // beginning another optional native observation/write after that boundary.
            if job.cancel.is_cancelled() {
                break;
            }
            let result = match &listings {
                ListingPublication::SingleRoot => provider.store_observed_index(
                    source_root,
                    &self.scan_roots,
                    cursor,
                    &scanned.covered_paths,
                    &scanned.dir_listings,
                ),
                ListingPublication::Grouped(listings) => provider.store_observed_index_owned(
                    source_root,
                    cursor,
                    listings.get(ordinal).iter().copied(),
                ),
                ListingPublication::Unavailable => continue,
            };
            if let Err(error) = result {
                writer.send(JunkSessionEventKind::CacheWarning(JunkSessionFailure::new(
                    "cache_index_write_failed",
                    error.to_string(),
                )))?;
            }
        }
        Ok(())
    }
}

fn cache_grouping_warning(
    writer: &mut Writer,
    cancel: &CancellationToken,
) -> Result<(), JunkSessionFailure> {
    if !cancel.is_cancelled() {
        writer.send(JunkSessionEventKind::CacheWarning(JunkSessionFailure::new(
            "cache_grouping_unavailable",
            "optional cache publication omitted: auxiliary budget or native evidence unavailable",
        )))?;
    }
    Ok(())
}

/// Shares lossless native attribution between full publication and selected fragment previews.
/// A missing locator invalidates the entire optional view: it cannot imply an absent candidate.
fn group_candidates<'a>(
    scope: &RootScope<'_>,
    pending: &'a Rows,
    selected: Option<&[PathBuf]>,
    budget: &mut GroupingBudget,
    cancel: &CancellationToken,
) -> Option<RootGroups<&'a JunkSessionCandidate>> {
    group_native(
        scope,
        pending.values().map(Arc::as_ref),
        |row| row.observed_native_path(),
        selected,
        budget,
        cancel,
    )
}

/// Projects one root at a time; all-root views retain references rather than cloned payloads.
fn stored_candidates(
    rows: &[&JunkSessionCandidate],
    cancel: &CancellationToken,
) -> Option<Vec<StoredJunkCandidate>> {
    if cancel.is_cancelled() {
        return None;
    }
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        if cancel.is_cancelled() {
            return None;
        }
        let mut stored = StoredJunkCandidate::from_candidate(&row.candidate);
        stored.aggregate = row.directory_aggregate().cloned();
        result.push(stored);
    }
    (!cancel.is_cancelled()).then_some(result)
}

#[cfg(test)]
#[path = "cache_benchmark.rs"]
mod benchmark;

fn historical_aggregate(stored: &StoredJunkCandidate, entry: &ScannedEntry) -> DirectoryAggregate {
    if let Some(aggregate) = &stored.aggregate
        && aggregate.scan_entry_id().ok().as_ref() == Some(&stored.entry_id)
        && aggregate.scan_id == entry.scan_id
    {
        return crate::stale_preview_aggregate(aggregate);
    }
    // Older records only have report size. Allocation evidence and directory inode lengths
    // cannot be used as a recursive logical total. Missing counts remain unknown, never zero.
    let unknown = ByteValue::Unknown {
        reason: ReasonCode::NotRevalidated,
    };
    DirectoryAggregate {
        scan_id: entry.scan_id.clone(),
        directory_identity: stored.entry_id.to_string(),
        revision: DecimalU128::ZERO,
        apparent_logical_bytes: if stored.size_is_logical {
            stored.reclaimable.clone()
        } else {
            unknown.clone()
        },
        unique_logical_bytes: unknown.clone(),
        filesystem_reported_allocated_bytes: unknown.clone(),
        potentially_reclaimable_bytes: unknown,
        direct_child_count: CountValue::Unknown {
            reason: ReasonCode::NotRevalidated,
        },
        recursive_entry_count: CountValue::Unknown {
            reason: ReasonCode::NotRevalidated,
        },
        coverage: Coverage {
            state: CoverageState::Incomplete,
            complete: false,
            details_lost: true,
            incomplete_reasons: vec![ReasonCode::NotRevalidated],
            provenance: FieldProvenance::StalePreview {
                observed_at: crate::timestamp_now(),
            },
        },
        arithmetic_state: ArithmeticState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_allocation_does_not_turn_into_recursive_logical_size_or_known_counts() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let scanned = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
            .unwrap();
        let source = &scanned.roots[0];
        let stored = StoredJunkCandidate {
            path: source.display_path.clone(),
            rule_id: "rust_target".into(),
            risk: "R1".into(),
            reclaimable: ByteValue::Known {
                value: DecimalU128::new(8192),
            },
            evidence: String::new(),
            source_reviewed_at: String::new(),
            references: Vec::new(),
            entry_id: source
                .validated_identity()
                .unwrap()
                .unwrap()
                .entry_id
                .clone(),
            ancestor_ids: BTreeSet::new(),
            size_is_logical: false,
            source_entry: Some(source.clone()),
            git_scan_facts: None,
            aggregate: None,
        };
        let aggregate = historical_aggregate(&stored, source);
        assert!(matches!(
            aggregate.apparent_logical_bytes,
            ByteValue::Unknown { .. }
        ));
        assert!(matches!(
            aggregate.recursive_entry_count,
            CountValue::Unknown { .. }
        ));
        assert!(!aggregate.coverage.complete);
    }
}
