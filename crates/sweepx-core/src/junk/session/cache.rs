//! Optional cache work stays on the session worker. Historical rows never become current by replay.

use super::*;
use crate::junk::cache::{
    CacheReader, StoredJunkCandidate, StoredJunkRoot,
    grouping::{
        DEFAULT_GROUPING_BYTES, GroupingBudget, RootGroups, RootScope, group_native, group_sources,
    },
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
        let records = reader
            .historical_roots_scoped_with_cancel(&self.scan_roots, &self.scan_roots, &job.cancel)
            .into_iter()
            .flatten()
            .collect();
        self.restore_records(records, service, rules_digest, job, writer)
    }

    pub(super) fn restore_regular_history(
        &mut self,
        reader: &mut CacheReader,
        service: &JunkService,
        rules_digest: [u8; 32],
        job: &Job,
        writer: &mut Writer,
    ) -> Result<(), JunkSessionFailure> {
        let records = reader.historical_session(&self.history_scope(), &job.cancel);
        if records.is_empty() {
            return Ok(());
        }
        let Ok(roots) =
            normalize_discovered_roots(records.iter().map(StoredJunkRoot::root_path).collect())
        else {
            return Ok(());
        };
        self.scan_roots = roots;
        self.restore_records(records, service, rules_digest, job, writer)
    }

    fn restore_records(
        &mut self,
        records: Vec<StoredJunkRoot>,
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
        for record in records {
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
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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
        if job.cancel.is_cancelled() || scanned.observed_roots.is_empty() {
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
        }
        .or_else(|| job.paths.clone());
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
        let mut old = if selected.is_some() || partial {
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
        let generation = format!(
            "{:039}:{}:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            self.session_id,
            job.revision.0
        );
        for (ordinal, root) in self.scan_roots.iter().enumerate() {
            if job.cancel.is_cancelled() {
                break;
            }
            let Some(source) = sources.get(ordinal).first() else {
                continue;
            };
            if partial
                && old.get(ordinal).is_none_or(Option::is_none)
                && reader.has_root_record(root)
            {
                // Unknown older rows survive a partial scan, including a refused cache read.
                continue;
            }
            let Some(stored) = stored_candidates(candidates.get(ordinal), &job.cancel) else {
                cache_grouping_warning(writer, &job.cancel)?;
                continue;
            };
            let sparse = stored.sparse;
            let mut previous = old.get_mut(ordinal).and_then(Option::take);
            if sparse && previous.is_none() {
                previous = reader
                    .historical_roots_scoped_with_cancel(
                        std::slice::from_ref(root),
                        &self.scan_roots,
                        &job.cancel,
                    )
                    .pop()
                    .flatten();
                if previous.is_none() && reader.has_root_record(root) {
                    continue;
                }
            }
            let mut record = StoredJunkRoot::capture_historical_with_rule_bytes(
                source,
                stored.candidates,
                context,
                &self.request.project_rule_bytes,
                super::super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
            );
            if (partial || sparse)
                && let Some(previous) = previous.take()
            {
                // A sparse preview cannot prove that omitted siblings disappeared, even when
                // the filesystem traversal itself was complete.
                record =
                    record.map(|fresh| previous.merge_observed_preview(fresh.into_candidates()));
            } else if let Some(paths) = &selected {
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
                record.bind_session_scope(&self.history_scope(), &generation, selected.is_none());
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

struct PreviewProjection {
    candidates: Vec<StoredJunkCandidate>,
    sparse: bool,
}

/// Projects one root at a time. Large roots retain a sparse first paint instead of losing every
/// historical row. Prefer outer candidates, then larger known/lower-bound sizes. Omitted rows
/// never imply absence or current coverage. An individually oversized row still preserves old
/// storage, and cancellation never publishes a replacement.
fn stored_candidates(
    rows: &[&JunkSessionCandidate],
    cancel: &CancellationToken,
) -> Option<PreviewProjection> {
    if cancel.is_cancelled() {
        return None;
    }
    let limit = crate::junk::cache::Limits::default().entry_bytes;
    let mut remaining = limit.checked_sub(
        rows.len()
            .saturating_mul(std::mem::size_of::<StoredJunkCandidate>()),
    )?;
    if rows.iter().any(|row| row.cost() > remaining) {
        return None;
    }
    let cost = rows
        .iter()
        .try_fold(0usize, |sum, row| sum.checked_add(row.cost()))?;
    let sparse = cost > remaining;
    let mut prioritized = Vec::new();
    let rows = if sparse {
        remaining = remaining.checked_sub(std::mem::size_of_val(rows))?;
        prioritized.extend_from_slice(rows);
        let bytes = |row: &JunkSessionCandidate| match row.logical_bytes() {
            ByteValue::Known { value } | ByteValue::LowerBound { value, .. } => Some(value.0),
            _ => None,
        };
        prioritized.sort_unstable_by(|left, right| {
            left.candidate
                .ancestor_ids
                .len()
                .cmp(&right.candidate.ancestor_ids.len())
                .then_with(|| bytes(right).cmp(&bytes(left)))
                .then_with(|| left.candidate.entry_id.cmp(&right.candidate.entry_id))
        });
        &prioritized
    } else {
        rows
    };
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        if cancel.is_cancelled() {
            return None;
        }
        let Some(next) = remaining.checked_sub(row.cost()) else {
            continue;
        };
        remaining = next;
        let mut stored = StoredJunkCandidate::from_candidate(&row.candidate);
        stored.aggregate = row.directory_aggregate().cloned();
        result.push(stored);
    }
    (!cancel.is_cancelled()).then_some(PreviewProjection {
        candidates: result,
        sparse,
    })
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
            monitor: None,
            watch_disabled: false,
            watch_warning: None,
            watch_roots: Vec::new(),
            watch_checked: std::time::Instant::now(),
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
            paths: None,
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
    fn cancelled_and_oversized_projections_preserve_previous_history() {
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
    fn partial_scans_publish_positive_history_without_erasing_unobserved_siblings() {
        let (_guard, root, cache) = fixture();
        let (old_scan, old_rows) = scan(&root);
        let worker = make_worker(&root, &cache);
        // A cold partial run now contributes a useful, explicitly historical first paint.
        assert!(publish(&worker, &cache, &old_scan, &old_rows, &job(), true).is_empty());
        assert_eq!(restore(&mut make_worker(&root, &cache), &cache).len(), 2);
        fs::write(root.join("a/target/payload"), b"new-positive-observation").unwrap();
        fs::write(
            root.join("b/target/payload"),
            b"not-observed-by-this-partial-scope",
        )
        .unwrap();
        let (fresh_scan, mut fresh_rows) = scan(&root);
        fresh_rows.retain(|_, row| row.observed_native_path() == Some(root.join("a/target")));
        assert!(publish(&worker, &cache, &fresh_scan, &fresh_rows, &job(), true).is_empty());
        let restored = restore(&mut make_worker(&root, &cache), &cache);
        let amounts: BTreeMap<_, _> = restored
            .into_iter()
            .map(|(state, row)| {
                assert_eq!(state, JunkSessionCandidateState::Historical);
                assert_eq!(
                    row.candidate.execution_policy,
                    crate::junk::candidate::JunkExecutionPolicy::NotChecked
                );
                (
                    row.observed_native_path().unwrap(),
                    row.logical_bytes().clone(),
                )
            })
            .collect();
        assert_eq!(
            amounts[&root.join("a/target")],
            sweepx_platform::known_u128(
                fs::metadata(root.join("a/target/payload"))
                    .unwrap()
                    .len()
                    .into()
            )
        );
        assert_eq!(
            amounts[&root.join("b/target")],
            sweepx_platform::known_u128(8)
        );
        assert_ne!(
            amounts[&root.join("b/target")],
            sweepx_platform::known_u128(
                fs::metadata(root.join("b/target/payload"))
                    .unwrap()
                    .len()
                    .into()
            )
        );
    }

    #[test]
    fn oversized_root_keeps_a_bounded_prioritized_historical_preview() {
        let (_guard, root, cache) = fixture();
        for n in 0..12 {
            let project = root.join(format!("large-{n}"));
            fs::create_dir_all(project.join("target")).unwrap();
            fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
            fs::write(project.join("target/payload"), vec![b'x'; 1024 * (n + 1)]).unwrap();
        }
        let (scanned, mut rows) = scan(&root);
        for row in rows.values_mut() {
            Arc::make_mut(row).candidate.references =
                vec!["bounded-fixture-reference".repeat(20_000)];
        }
        let worker = make_worker(&root, &cache);
        let projection = stored_candidates(
            &rows.values().map(Arc::as_ref).collect::<Vec<_>>(),
            &job().cancel,
        )
        .unwrap();
        assert!(projection.sparse);
        assert!(!projection.candidates.is_empty() && projection.candidates.len() < rows.len());
        assert!(publish(&worker, &cache, &scanned, &rows, &job(), true).is_empty());
        let restored = restore(&mut make_worker(&root, &cache), &cache);
        assert!(!restored.is_empty() && restored.len() < rows.len());
        let biggest = root.join("large-11/target");
        assert!(restored.iter().any(|(state, row)| {
            assert_eq!(*state, JunkSessionCandidateState::Historical);
            assert_eq!(
                row.candidate.execution_policy,
                crate::junk::candidate::JunkExecutionPolicy::NotChecked
            );
            row.observed_native_path() == Some(biggest.clone())
                && row.logical_bytes()
                    == &sweepx_platform::known_u128(u128::from(
                        fs::metadata(biggest.join("payload")).unwrap().len(),
                    ))
        }));
        // Every saved row remains useful on a subsequent partial run under the same bounds.
        assert!(publish(&worker, &cache, &scanned, &rows, &job(), true).is_empty());
        assert_eq!(
            restore(&mut make_worker(&root, &cache), &cache).len(),
            restored.len()
        );
    }

    #[test]
    fn regular_history_requires_request_rules_and_current_native_root_identity() {
        let (_guard, root, cache) = fixture();
        let (scanned, rows) = scan(&root);
        let worker = make_worker(&root, &cache);
        assert!(publish(&worker, &cache, &scanned, &rows, &job(), false).is_empty());
        let scope = worker.history_scope();
        let cancel = CancellationToken::new();
        assert_eq!(
            CacheReader::new(&cache)
                .historical_session(&scope, &cancel)
                .len(),
            1
        );
        assert!(
            CacheReader::new(&cache)
                .historical_session("different-request", &cancel)
                .is_empty()
        );
        assert!(
            CacheReader::with_rule_bytes(&cache, b"changed rules", b"changed platform rules")
                .historical_session(&scope, &cancel)
                .is_empty()
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            CacheReader::new(&cache)
                .historical_session(&scope, &cancelled)
                .is_empty()
        );
        // Keep the original object alive to make native replacement independent of inode reuse.
        fs::rename(&root, root.with_extension("previous-object")).unwrap();
        fs::create_dir(&root).unwrap();
        assert!(
            CacheReader::new(&cache)
                .historical_session(&scope, &cancel)
                .is_empty()
        );
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
