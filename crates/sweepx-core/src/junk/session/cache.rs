//! Optional cache work stays on the session worker. Historical rows never become current by replay.

use super::*;
use crate::junk::cache::{
    CacheReader, StoredJunkCandidate, StoredJunkRoot, provider::SubtreeCacheProvider,
};
use sweepx_model::{
    ArithmeticState, ByteValue, CountValue, Coverage, CoverageState, DecimalU128, FieldProvenance,
    ReasonCode,
};

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
                if self.preview_keys.len() >= self.request.limits.max_candidates {
                    // Preview omission is not a fresh-scan coverage gap. Leave capacity and
                    // current native observations independent of optional historical payloads.
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
                candidate.blockers.push("historical_cache".into());
                let Some(key) = candidate_key(&candidate, &path) else {
                    continue;
                };
                if !self.preview_keys.insert(key) {
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
                    self.preview_keys.remove(&key);
                    continue;
                }
                writer.send(JunkSessionEventKind::Candidate {
                    key,
                    state: JunkSessionCandidateState::Historical,
                    rules_digest,
                    row,
                })?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn store_cache(
        &self,
        directory: &Path,
        cursor: crate::FsEventId,
        provider: &SubtreeCacheProvider,
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
        for root in &self.scan_roots {
            if job.cancel.is_cancelled() {
                break;
            }
            let Some(source_root) = scanned
                .observed_roots
                .iter()
                .find(|source| native_path(source).as_ref() == Some(root))
            else {
                continue;
            };
            // Selected refresh does not carry every candidate in an original root; it may
            // refresh file facts but must never publish a truncated whole-root report.
            if job.selected.is_none()
                && !partial
                && root
                    .to_str()
                    .is_some_and(|path| scanned.covered_paths.get(path) == Some(&true))
                && let Some(context) = context
            {
                let rows = pending
                    .values()
                    .filter(|row| {
                        row.observed_native_path().is_some_and(|path| {
                            self.scan_roots
                                .iter()
                                .filter(|root| path.starts_with(root))
                                .max_by_key(|root| root.components().count())
                                == Some(root)
                        })
                    })
                    .map(|row| {
                        let mut stored = StoredJunkCandidate::from_candidate(&row.candidate);
                        stored.aggregate = row.directory_aggregate().cloned();
                        stored
                    })
                    .collect();
                let result = StoredJunkRoot::capture_with_rule_bytes(
                    root,
                    rows,
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
            if let Err(error) = provider.store_observed_index(
                source_root,
                &self.scan_roots,
                cursor,
                &scanned.covered_paths,
                &scanned.dir_listings,
            ) {
                writer.send(JunkSessionEventKind::CacheWarning(JunkSessionFailure::new(
                    "cache_index_write_failed",
                    error.to_string(),
                )))?;
            }
        }
        Ok(())
    }
}

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
