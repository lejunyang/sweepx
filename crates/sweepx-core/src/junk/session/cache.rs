//! Optional cache work stays on the session worker. Historical rows never become current by replay.

use super::*;
use crate::junk::cache::{
    CacheReader, StoredJunkCandidate, StoredJunkRoot,
    grouping::{
        DEFAULT_GROUPING_BYTES, GroupingBudget, RootGroups, RootScope, group_native, group_sources,
    },
};
#[cfg(target_os = "macos")]
use crate::junk::cache::{grouping::group_listings, provider::SubtreeCacheProvider};
use sweepx_model::{
    ArithmeticState, ByteValue, CountValue, Coverage, CoverageState, DecimalU128, FieldProvenance,
    ReasonCode,
};

/// A single root can project directly and stop at its optional wire limit. Only multiple roots
/// need a shared partition; unavailable views must never be treated as successfully empty facts.
#[cfg(target_os = "macos")]
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
            super::super::platform::select_platform_rules(&self.request.platform_rule_ids)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for record in reader
            .historical_roots_scoped_with_cancel(&self.scan_roots, &self.scan_roots, &job.cancel)
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

    /// Historical-only publication does not qualify a root/file index as unchanged. This policy
    /// is exercised on macOS too; each platform retains its native storage/runtime boundary.
    #[cfg(any(target_os = "linux", target_os = "windows", test))]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn store_history(
        &self,
        directory: &Path,
        reader: &mut CacheReader,
        scanned: &sweepx_scanner::ClassifiedScan,
        pending: &Rows,
        service: &JunkService,
        platform: &PlatformJunkSetup,
        job: &Job,
        partial: bool,
        writer: &mut Writer,
    ) -> Result<(), JunkSessionFailure> {
        if partial || job.cancel.is_cancelled() || scanned.observed_roots.is_empty() {
            return Ok(());
        }
        let selected = job.selected.as_ref().map(|keys| {
            keys.iter()
                .map(|key| {
                    self.current
                        .get(key)
                        .and_then(|row| row.observed_native_path())
                })
                .collect::<Option<Vec<_>>>()
        });
        let selected = match selected {
            Some(None) => {
                cache_grouping_warning(writer, &job.cancel)?;
                return Ok(());
            }
            Some(Some(paths)) => Some(paths),
            None => None,
        };
        let mut budget = GroupingBudget::new(DEFAULT_GROUPING_BYTES);
        let prepared = RootScope::new(&self.scan_roots, &mut budget).and_then(|scope| {
            let sources = group_sources(&scope, &scanned.observed_roots, &mut budget, &job.cancel)?;
            let candidates = group_candidates(
                &scope,
                pending,
                selected.as_deref(),
                &mut budget,
                &job.cancel,
            )?;
            Some((sources, candidates))
        });
        let Some((sources, candidates)) = prepared else {
            cache_grouping_warning(writer, &job.cancel)?;
            return Ok(());
        };
        if sources.is_empty() {
            return Ok(());
        }
        // Old siblings are presentation only. No filesystem-history claim is needed to retain
        // them as historical; root/rules/scope still have to match under the shared read budget.
        let mut old = if selected.is_some() {
            reader.historical_roots_scoped_with_cancel(
                &self.scan_roots,
                &self.scan_roots,
                &job.cancel,
            )
        } else {
            Vec::new()
        };
        let context = service
            .with_platform(&platform.rules, &platform.evidence)
            .classification_context_digest();
        for (ordinal, root) in self.scan_roots.iter().enumerate() {
            if job.cancel.is_cancelled() {
                break;
            }
            let Some(source) = sources.get(ordinal).first() else {
                continue;
            };
            let Some(stored) = stored_candidates(candidates.get(ordinal), &job.cancel) else {
                cache_grouping_warning(writer, &job.cancel)?;
                continue;
            };
            let mut record = StoredJunkRoot::capture_historical_with_rule_bytes(
                source,
                stored,
                context,
                &self.request.project_rule_bytes,
                super::super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
            );
            if let Some(paths) = &selected {
                let previous = old.get_mut(ordinal).and_then(Option::take);
                record = match (record, previous) {
                    (Ok(fresh), Some(previous)) => {
                        Ok(previous.merge_preview(paths, fresh.into_candidates(), None))
                    }
                    (result, _) => result,
                };
            }
            let result = record.and_then(|mut record| {
                if !record.matches_observed_root(source) {
                    return Err(std::io::Error::other(
                        "historical root changed after traversal",
                    ));
                }
                record.bind_scope(&self.scan_roots);
                if job.cancel.is_cancelled() {
                    return Ok(());
                }
                match &self.request.cache_state_root {
                    Some(root) => crate::junk::cache::write_in_state(root, &record),
                    None => crate::junk::cache::write(directory, &record),
                }
            });
            if let Err(error) = result {
                writer.send(JunkSessionEventKind::CacheWarning(JunkSessionFailure::new(
                    "cache_write_failed",
                    error.to_string(),
                )))?;
            }
            debug_assert!(root.is_absolute() && budget.used_bytes() <= DEFAULT_GROUPING_BYTES);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(target_os = "macos")]
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
                    match &self.request.cache_state_root {
                        Some(root) => crate::junk::cache::write_in_state(root, &record),
                        None => crate::junk::cache::write(directory, &record),
                    }
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
        pending
            .values()
            .map(Arc::as_ref)
            .filter(|row| row.directory_aggregate().is_some()),
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
    // One root's projection has an independent owned-data allowance. A wire cap applied after
    // cloning is too late to bound these copies; rejection preserves the previous cache record.
    let mut remaining = crate::junk::cache::Limits::default().entry_bytes;
    remaining = remaining.checked_sub(
        rows.len()
            .saturating_mul(std::mem::size_of::<StoredJunkCandidate>()),
    )?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        if cancel.is_cancelled() {
            return None;
        }
        let next = remaining.checked_sub(row.cost())?;
        remaining = next;
        let mut stored = StoredJunkCandidate::from_candidate(&row.candidate);
        stored.aggregate = row.directory_aggregate().cloned();
        result.push(stored);
    }
    (!cancel.is_cancelled()).then_some(result)
}

#[cfg(all(test, target_os = "macos"))]
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
    use std::fs;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        #[cfg(target_os = "linux")]
        let fixture = tempfile::tempdir_in("/dev/shm").unwrap();
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let base = fixture.path().canonicalize().unwrap();
        #[cfg(windows)]
        let base = fixture.path().to_path_buf();
        let root = base.join("projects");
        for (name, payload) in [("a", &b"aaaa"[..]), ("b", &b"bbbbbbbb"[..])] {
            let project = root.join(name);
            fs::create_dir_all(project.join("target")).unwrap();
            fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
            fs::write(project.join("target/payload"), payload).unwrap();
        }
        (fixture, root, base.join("cache"))
    }

    fn scan(root: &Path) -> (sweepx_scanner::ClassifiedScan, Rows) {
        let service = JunkService::built_in().unwrap();
        let scanned = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
            .scan_classified(
                &[ScanRoot::new(root.to_path_buf()).unwrap()],
                &CancellationToken::new(),
                &service,
                None,
            )
            .unwrap();
        let aggregates = scanned
            .summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect::<BTreeMap<_, _>>();
        let rows = scanned
            .summary
            .entries
            .iter()
            .filter_map(|entry| {
                let id = &entry.validated_identity().unwrap()?.entry_id;
                let candidate = service.interpret(
                    scanned.decisions.get(id)?,
                    entry,
                    &aggregates,
                    &[],
                    &Default::default(),
                )?;
                let path = native_path(entry)?;
                Some((
                    candidate_key(&candidate, &path)?,
                    Arc::new(JunkSessionCandidate {
                        candidate,
                        facts: JunkSessionFacts::Directory(Box::new(
                            (*aggregates.get(id.as_str())?).clone(),
                        )),
                    }),
                ))
            })
            .collect::<Rows>();
        assert_eq!(rows.len(), 2);
        (scanned, rows)
    }

    fn make_worker(root: &Path, cache: &Path) -> Worker {
        let mut request = JunkSessionRequest::new(vec![root.to_path_buf()]);
        request.cache_dir = Some(cache.to_path_buf());
        Worker {
            request,
            session_id: "historical-policy-contract".into(),
            current: Rows::new(),
            presentations: PresentationIndex::default(),
            scan_roots: vec![root.to_path_buf()],
        }
    }

    fn publish(
        worker: &Worker,
        cache: &Path,
        scanned: &sweepx_scanner::ClassifiedScan,
        rows: &Rows,
        job: &Job,
        partial: bool,
    ) -> Vec<JunkSessionEvent> {
        let shared = Arc::new(Shared::new(worker.request.limits));
        let mut writer = Writer::new(Arc::clone(&shared), job.revision, job.cancel.clone());
        worker
            .store_history(
                cache,
                &mut CacheReader::new(cache),
                scanned,
                rows,
                &JunkService::built_in().unwrap(),
                &PlatformJunkSetup::default(),
                job,
                partial,
                &mut writer,
            )
            .unwrap();
        let session = JunkSession { shared };
        std::iter::from_fn(|| session.try_next_event()).collect()
    }

    fn job() -> Job {
        Job {
            revision: JunkSessionRevision(1),
            selected: None,
            cancel: CancellationToken::new(),
        }
    }

    fn restore(
        worker: &mut Worker,
        cache: &Path,
    ) -> Vec<(JunkSessionCandidateState, Arc<JunkSessionCandidate>)> {
        let job = job();
        let shared = Arc::new(Shared::new(worker.request.limits));
        let mut writer = Writer::new(Arc::clone(&shared), job.revision, job.cancel.clone());
        worker
            .restore_history(
                &mut CacheReader::new(cache),
                &JunkService::built_in().unwrap(),
                [7; 32],
                &job,
                &mut writer,
            )
            .unwrap();
        let session = JunkSession { shared };
        std::iter::from_fn(|| session.try_next_event())
            .filter_map(|event| match event.kind {
                JunkSessionEventKind::Candidate { state, row, .. } => Some((state, row)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn historical_policy_publishes_and_restores_only_stale_non_executable_rows() {
        let (_guard, root, cache) = fixture();
        let (scanned, rows) = scan(&root);
        let worker = make_worker(&root, &cache);
        assert!(publish(&worker, &cache, &scanned, &rows, &job(), false).is_empty());
        let restored = restore(&mut make_worker(&root, &cache), &cache);
        assert_eq!(restored.len(), 2);
        for (state, row) in restored {
            assert_eq!(state, JunkSessionCandidateState::Historical);
            // Coverage describes the original observation; freshness and execution are separate.
            // Preserving that coverage must not strip the stale provenance or the history gate.
            assert!(row.complete());
            assert!(matches!(
                row.directory_aggregate().unwrap().coverage.provenance,
                FieldProvenance::StalePreview { .. }
            ));
            assert!(
                row.candidate
                    .blockers
                    .iter()
                    .any(|blocker| blocker == "historical_cache")
            );
            assert_eq!(
                row.candidate.execution_policy,
                crate::junk::candidate::JunkExecutionPolicy::NotChecked
            );
            assert!(row.candidate.git.is_none() && row.candidate.activity.is_none());
            let payload = row.observed_native_path().unwrap().join("payload");
            assert_eq!(
                row.logical_bytes(),
                &sweepx_platform::known_u128(u128::from(fs::metadata(payload).unwrap().len()))
            );
        }
    }

    #[test]
    fn selected_historical_merge_keeps_old_siblings_explicitly_stale_even_when_changed() {
        let (_guard, root, cache) = fixture();
        let (old_scan, old_rows) = scan(&root);
        let mut worker = make_worker(&root, &cache);
        publish(&worker, &cache, &old_scan, &old_rows, &job(), false);
        worker.current = old_rows;
        let key = *worker
            .current
            .iter()
            .find(|(_, row)| row.observed_native_path() == Some(root.join("a/target")))
            .unwrap()
            .0;
        fs::write(root.join("a/target/payload"), b"new-selected-payload").unwrap();
        fs::write(
            root.join("b/target/payload"),
            b"changed-unselected-payload-is-longer",
        )
        .unwrap();
        let (fresh_scan, fresh_rows) = scan(&root);
        let mut selected = job();
        selected.selected = Some(vec![key]);
        assert!(publish(&worker, &cache, &fresh_scan, &fresh_rows, &selected, false).is_empty());
        let restored = restore(&mut make_worker(&root, &cache), &cache);
        let facts = restored
            .into_iter()
            .map(|(state, row)| {
                assert_eq!(state, JunkSessionCandidateState::Historical);
                (
                    row.observed_native_path().unwrap(),
                    row.logical_bytes().clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            facts[&root.join("a/target")],
            sweepx_platform::known_u128(u128::from(
                fs::metadata(root.join("a/target/payload")).unwrap().len()
            ))
        );
        assert_eq!(
            facts[&root.join("b/target")],
            sweepx_platform::known_u128(8)
        );
        assert_ne!(
            facts[&root.join("b/target")],
            sweepx_platform::known_u128(u128::from(
                fs::metadata(root.join("b/target/payload")).unwrap().len()
            ))
        );
    }

    #[test]
    fn partial_cancelled_and_oversized_projections_preserve_previous_history() {
        let (_guard, root, cache) = fixture();
        let (scanned, mut rows) = scan(&root);
        let worker = make_worker(&root, &cache);
        publish(&worker, &cache, &scanned, &rows, &job(), false);
        let snapshot = || {
            fs::read_dir(&cache)
                .unwrap()
                .filter_map(|item| {
                    let item = item.unwrap();
                    let path = item.path();
                    (path.extension() == Some(std::ffi::OsStr::new("json")))
                        .then(|| (path.clone(), fs::read(path).unwrap()))
                })
                .collect::<BTreeMap<_, _>>()
        };
        let before = snapshot();
        assert_eq!(before.len(), 1);
        publish(&worker, &cache, &scanned, &rows, &job(), true);
        assert_eq!(snapshot(), before);
        let cancelled = job();
        cancelled.cancel.cancel();
        publish(&worker, &cache, &scanned, &rows, &cancelled, false);
        assert_eq!(snapshot(), before);
        let (&key, row) = rows.first_key_value().unwrap();
        let mut candidate = row.candidate.clone();
        candidate.references = vec!["x".repeat(5 * 1024 * 1024)];
        let facts = row.facts.clone();
        rows.insert(key, Arc::new(JunkSessionCandidate { candidate, facts }));
        let events = publish(&worker, &cache, &scanned, &rows, &job(), false);
        assert!(
            events
                .iter()
                .any(|event| matches!(event.kind, JunkSessionEventKind::CacheWarning(_)))
        );
        assert_eq!(snapshot(), before);
    }

    #[test]
    fn legacy_allocation_does_not_turn_into_recursive_logical_size_or_known_counts() {
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = fixture.path().canonicalize().unwrap();
        #[cfg(windows)]
        let root = fixture.path().to_path_buf();
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
