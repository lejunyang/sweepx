//! Opt-in comparison of cache preparation, excluding traversal, tools, events and disk writes.
//! The legacy reference below preserves cfcaaa3's per-root attribution loops. It is only a
//! migration oracle: neither path supplies native execution authority or a second classifier.

use super::*;
use crate::junk::cache::grouping::{
    DEFAULT_GROUPING_BYTES, GroupingBudget, RootScope, group_listings,
};
use crate::junk::cache::{Limits, StoredSubtreeIndex};
use std::fs;
use std::time::Instant;
use sweepx_scanner::DirListing;

struct Fixture {
    _directory: tempfile::TempDir,
    base: PathBuf,
    rows: Rows,
    scanned: sweepx_scanner::ClassifiedScan,
}

impl Fixture {
    fn new(count: usize) -> Self {
        struct Collect<'a> {
            service: &'a JunkService,
            rows: Rows,
        }
        impl ClassifiedScanObserver for Collect<'_> {
            fn on_candidate(
                &mut self,
                entry: &ScannedEntry,
                decision: &str,
                aggregate: &DirectoryAggregate,
            ) {
                let aggregates =
                    BTreeMap::from([(aggregate.directory_identity.as_str(), aggregate)]);
                let candidate = self
                    .service
                    .interpret(decision, entry, &aggregates, &[], &Default::default())
                    .unwrap();
                let path = native_path(entry).unwrap();
                let key = candidate_key(&candidate, &path).unwrap();
                self.rows.insert(
                    key,
                    Arc::new(JunkSessionCandidate {
                        candidate,
                        facts: JunkSessionFacts::Directory(Box::new(aggregate.clone())),
                    }),
                );
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().canonicalize().unwrap();
        for index in 0..count {
            let project = base
                .join(format!("g{:02}", index % 8))
                .join(format!("h{:02}", (index / 8) % 8))
                .join(format!("i{:02}", (index / 64) % 4))
                .join(format!("p{index:05}"));
            fs::create_dir_all(project.join("target")).unwrap();
            fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
            fs::write(project.join("target/payload"), b"12345678").unwrap();
        }
        let service = JunkService::built_in().unwrap();
        let mut collector = Collect {
            service: &service,
            rows: Rows::new(),
        };
        let scanned = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
            .scan_classified_with_observer(
                &[ScanRoot::new(base.clone()).unwrap()],
                &CancellationToken::new(),
                &service,
                None,
                &mut collector,
            )
            .unwrap();
        assert_eq!(collector.rows.len(), count);
        Self {
            _directory: directory,
            base,
            rows: collector.rows,
            scanned,
        }
    }

    fn roots(&self, count: usize) -> Vec<PathBuf> {
        match count {
            1 => vec![self.base.clone()],
            8 => (0..8).map(|g| self.base.join(format!("g{g:02}"))).collect(),
            64 => (0..8)
                .flat_map(|g| {
                    (0..8).map(move |h| self.base.join(format!("g{g:02}")).join(format!("h{h:02}")))
                })
                .collect(),
            256 => (0..8)
                .flat_map(|g| {
                    (0..8).flat_map(move |h| {
                        (0..4).map(move |i| {
                            self.base
                                .join(format!("g{g:02}"))
                                .join(format!("h{h:02}"))
                                .join(format!("i{i:02}"))
                        })
                    })
                })
                .collect(),
            _ => panic!("unsupported benchmark scope"),
        }
    }

    fn inputs(&self, count: usize) -> (Rows, BTreeMap<String, DirListing>) {
        let rows: Rows = self
            .rows
            .iter()
            .take(count)
            .map(|(key, row)| (*key, Arc::clone(row)))
            .collect();
        assert_eq!(rows.len(), count);
        let mut paths = BTreeSet::new();
        for row in rows.values() {
            let native = row.observed_native_path().unwrap();
            for path in native
                .ancestors()
                .take_while(|path| path.starts_with(&self.base))
            {
                paths.insert(path.to_str().unwrap().to_owned());
            }
        }
        let listings = self
            .scanned
            .dir_listings
            .iter()
            .filter(|(path, _)| paths.contains(*path))
            .map(|(path, listing)| (path.clone(), listing.clone()))
            .collect();
        (rows, listings)
    }
}

fn project_rows<'a>(
    rows: impl Iterator<Item = &'a Arc<JunkSessionCandidate>>,
) -> Vec<StoredJunkCandidate> {
    rows.map(|row| {
        let mut stored = StoredJunkCandidate::from_candidate(&row.candidate);
        stored.aggregate = row.directory_aggregate().cloned();
        stored
    })
    .collect()
}

fn legacy_candidates(roots: &[PathBuf], rows: &Rows) -> Vec<Vec<StoredJunkCandidate>> {
    roots
        .iter()
        .map(|root| {
            project_rows(rows.values().filter(|row| {
                row.observed_native_path().is_some_and(|path| {
                    roots
                        .iter()
                        .filter(|candidate| path.starts_with(candidate))
                        .max_by_key(|candidate| candidate.components().count())
                        == Some(root)
                })
            }))
        })
        .collect()
}

fn legacy_index(
    root: &Path,
    roots: &[PathBuf],
    covered: &BTreeMap<String, bool>,
    listings: &BTreeMap<String, DirListing>,
) -> StoredSubtreeIndex {
    let mut remaining = Limits::default()
        .entry_bytes
        .saturating_sub(1024 + root.as_os_str().len().saturating_mul(6));
    let mut projected_coverage = BTreeMap::new();
    let mut projected_listings = BTreeMap::new();
    // Exact legacy projection, including its per-root JSON allowance and ordered truncation.
    for (path, listing) in listings {
        if covered.get(path) != Some(&true)
            || roots
                .iter()
                .filter(|candidate| Path::new(path).starts_with(candidate))
                .max_by_key(|candidate| candidate.components().count())
                .map(PathBuf::as_path)
                != Some(root)
        {
            continue;
        }
        let cost = path.len().saturating_mul(12).saturating_add(128);
        if cost > remaining {
            break;
        }
        remaining -= cost;
        let mut saved = crate::junk::cache::StoredDirListing::default();
        for (name, bytes) in &listing.files {
            let cost = name.len().saturating_mul(6).saturating_add(64);
            if cost > remaining {
                break;
            }
            remaining -= cost;
            saved.files.insert(name.clone(), *bytes);
        }
        projected_coverage.insert(path.clone(), true);
        projected_listings.insert(path.clone(), saved);
    }
    // The public constructor performs the same single native root metadata observation. These
    // isolated fixtures stay unchanged throughout measurement; metadata is captured after the
    // reference projection because the stored fields intentionally remain private.
    StoredSubtreeIndex::new(root, 42, projected_coverage, projected_listings).unwrap()
}

fn grouped_candidates(roots: &[PathBuf], rows: &Rows) -> Vec<Vec<StoredJunkCandidate>> {
    let mut budget = GroupingBudget::new(DEFAULT_GROUPING_BYTES);
    let scope = RootScope::new(roots, &mut budget).unwrap();
    let groups =
        group_candidates(&scope, rows, None, &mut budget, &CancellationToken::new()).unwrap();
    (0..scope.len())
        .map(|index| stored_candidates(groups.get(index), &CancellationToken::new()).unwrap())
        .collect()
}

fn grouped_indexes(
    roots: &[PathBuf],
    covered: &BTreeMap<String, bool>,
    listings: &BTreeMap<String, DirListing>,
) -> Vec<StoredSubtreeIndex> {
    // Match publication's single-root fast path: capture stops when the per-root wire
    // allowance fills, without first partitioning the optional tail of all listings.
    if roots.len() == 1 {
        return vec![StoredSubtreeIndex::capture(&roots[0], roots, 42, covered, listings).unwrap()];
    }
    let mut budget = GroupingBudget::new(DEFAULT_GROUPING_BYTES);
    let scope = RootScope::new(roots, &mut budget).unwrap();
    let groups = group_listings(
        &scope,
        covered,
        listings,
        &mut budget,
        &CancellationToken::new(),
    )
    .unwrap();
    roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            StoredSubtreeIndex::capture_owned(root, 42, groups.get(index).iter().copied()).unwrap()
        })
        .collect()
}

fn legacy_cli_candidates(
    roots: &[PathBuf],
    candidates: &[JunkCandidate],
    aggregates: &[DirectoryAggregate],
) -> Vec<Vec<StoredJunkCandidate>> {
    roots
        .iter()
        .enumerate()
        .map(|(ordinal, _)| {
            candidates
                .iter()
                .filter(|candidate| {
                    // cfcaaa3's CLI used display-prefix ownership and a linear aggregate lookup.
                    // This reference is exercised only with ordinary canonical UTF-8 fixtures.
                    let mut best = None;
                    for (index, root) in roots.iter().enumerate() {
                        let text = root.display().to_string();
                        if (candidate.path == text
                            || candidate.path.starts_with(&format!("{text}/")))
                            && best.is_none_or(|(_, length)| text.len() > length)
                        {
                            best = Some((index, text.len()));
                        }
                    }
                    best.map(|(index, _)| index) == Some(ordinal)
                })
                .map(|candidate| {
                    let mut stored = StoredJunkCandidate::from_candidate(candidate);
                    stored.aggregate = aggregates
                        .iter()
                        .find(|aggregate| {
                            aggregate.directory_identity == candidate.entry_id.as_str()
                        })
                        .cloned();
                    stored
                })
                .collect()
        })
        .collect()
}

fn grouped_cli_candidates(
    roots: &[PathBuf],
    candidates: &[JunkCandidate],
    aggregates: &[DirectoryAggregate],
) -> Vec<Vec<StoredJunkCandidate>> {
    let cancel = CancellationToken::new();
    let grouped = crate::junk::cache::publication::CandidateCacheGroups::prepare(
        roots, candidates, aggregates, &cancel,
    )
    .unwrap();
    (0..roots.len())
        .map(|ordinal| grouped.project_root(ordinal, &cancel).unwrap())
        .collect()
}

#[test]
fn candidate_groups_use_native_scope_and_decline_incomplete_optional_projection() {
    let fixture = Fixture::new(16);
    let nested = fixture.base.join("g00");
    let roots = vec![fixture.base.clone(), nested.clone()];
    let rows: Rows = fixture
        .rows
        .iter()
        .map(|(key, row)| {
            let mut row = (**row).clone();
            // A report spelling is intentionally assigned to a different root. No native
            // binding is forged, and no filesystem operation is performed through that path.
            row.candidate.path = nested.join("display-only").to_string_lossy().into_owned();
            (*key, Arc::new(row))
        })
        .collect();
    let mut budget = GroupingBudget::new(DEFAULT_GROUPING_BYTES);
    let scope = RootScope::new(&roots, &mut budget).unwrap();
    let cancel = CancellationToken::new();
    let groups = group_candidates(&scope, &rows, None, &mut budget, &cancel).unwrap();
    let actual: Vec<BTreeSet<PathBuf>> = (0..2)
        .map(|owner| {
            groups
                .get(owner)
                .iter()
                .map(|row| row.observed_native_path().unwrap())
                .collect()
        })
        .collect();
    let expected_nested: BTreeSet<_> = [0, 8]
        .map(|index| {
            nested
                .join(format!("h{:02}", (index / 8) % 8))
                .join("i00")
                .join(format!("p{index:05}/target"))
        })
        .into_iter()
        .collect();
    assert_eq!(actual[1], expected_nested);
    assert_eq!(actual[0].len(), 14);
    assert!(actual[0].is_disjoint(&actual[1]));
    assert_eq!(
        legacy_candidates(&roots, &rows),
        grouped_candidates(&roots, &rows)
    );

    let mut budget = GroupingBudget::new(DEFAULT_GROUPING_BYTES);
    let selected = [nested];
    let selected_groups =
        group_candidates(&scope, &rows, Some(&selected), &mut budget, &cancel).unwrap();
    assert!(selected_groups.get(0).is_empty());
    assert_eq!(selected_groups.get(1).len(), 2);

    let mut missing = rows;
    Arc::make_mut(missing.values_mut().next().unwrap())
        .candidate
        .source_entry = None;
    assert!(
        group_candidates(
            &scope,
            &missing,
            None,
            &mut GroupingBudget::new(DEFAULT_GROUPING_BYTES),
            &cancel,
        )
        .is_none()
    );
    assert!(
        group_candidates(
            &scope,
            &fixture.rows,
            None,
            &mut GroupingBudget::new(0),
            &cancel,
        )
        .is_none()
    );
    cancel.cancel();
    assert!(
        group_candidates(
            &scope,
            &fixture.rows,
            None,
            &mut GroupingBudget::new(DEFAULT_GROUPING_BYTES),
            &cancel,
        )
        .is_none()
    );
}

fn elapsed_projection<T>(operation: impl FnOnce() -> T) -> u128 {
    let start = Instant::now();
    let result = std::hint::black_box(operation());
    let elapsed = start.elapsed().as_nanos();
    std::hint::black_box(&result);
    elapsed
}

#[test]
fn cached_roots_without_observed_publication_sources_skip_optional_preparation() {
    let mut fixture = Fixture::new(8);
    let cache = fixture.base.join("cache-must-remain-absent");
    let roots = vec![fixture.base.clone()];
    let request = JunkSessionRequest::new(roots.clone());
    let limits = request.limits;
    let worker = Worker {
        request,
        session_id: "cache-preparation-test".into(),
        current: Rows::new(),
        presentations: PresentationIndex::default(),
        scan_roots: roots,
        monitor: None,
        watch_disabled: false,
        watch_warning: None,
        watch_roots: Vec::new(),
        watch_checked: std::time::Instant::now(),
    };
    let job = Job {
        revision: JunkSessionRevision(1),
        selected: None,
        paths: None,
        cancel: CancellationToken::new(),
    };
    let shared = Arc::new(Shared::new(limits));
    let mut writer = Writer::new(Arc::clone(&shared), job.revision, job.cancel.clone());
    let service = JunkService::built_in().unwrap();
    let mut reader = crate::junk::cache::CacheReader::new(&cache);
    // Invalid optional candidate input would fail grouping and emit a warning if the warm
    // path unnecessarily visited it. No-source publication must not inspect pending rows.
    Arc::make_mut(fixture.rows.values_mut().next().unwrap())
        .candidate
        .source_entry = None;
    fixture.scanned.observed_roots.clear();
    worker
        .store_history(
            &cache,
            &mut reader,
            &fixture.scanned,
            &fixture.rows,
            &service,
            &PlatformJunkSetup::default(),
            &job,
            false,
            &mut writer,
        )
        .unwrap();
    assert!(shared.pop().is_none());
    assert!(!cache.exists());
}

#[test]
#[ignore = "opt-in release cache-preparation microbenchmark; performs no Trash or cache write"]
fn benchmark_multi_root_cache_preparation() {
    if cfg!(debug_assertions) {
        panic!("measure the release build explicitly");
    }
    let fixture = Fixture::new(8192);
    for row in fixture.rows.values() {
        let payload = row.observed_native_path().unwrap().join("payload");
        assert_eq!(fs::read(&payload).unwrap(), b"12345678");
        assert_eq!(fs::symlink_metadata(payload).unwrap().len(), 8);
    }
    let started = Instant::now();
    // A follow-up may isolate the changed single-root route while retaining the original
    // fixed repetitions and equality oracle. This is an explicit workload selection.
    let single_root_only =
        std::env::var_os("SWEEPX_CACHE_BENCH_SINGLE_ROOT_ONLY").is_some_and(|value| value == "1");
    for (root_count, candidate_count) in [
        (1, 128),
        (8, 1024),
        (64, 1024),
        (256, 1024),
        (1, 8192),
        (8, 8192),
        (64, 8192),
    ] {
        if single_root_only && root_count != 1 {
            continue;
        }
        // Inputs come from one complete native observation. Fixed key-order subsets define
        // each case; setup, traversal and equality checks are outside the measured phases.
        let roots = fixture.roots(root_count);
        let (rows, listings) = fixture.inputs(candidate_count);
        assert_eq!(
            legacy_candidates(&roots, &rows),
            grouped_candidates(&roots, &rows)
        );
        let old: Vec<_> = roots
            .iter()
            .map(|root| legacy_index(root, &roots, &fixture.scanned.covered_paths, &listings))
            .collect();
        let new = grouped_indexes(&roots, &fixture.scanned.covered_paths, &listings);
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::to_value(&new).unwrap()
        );
        drop((old, new));
        let mut candidate_legacy = Vec::new();
        let mut candidate_grouped = Vec::new();
        let mut index_legacy = Vec::new();
        let mut index_grouped = Vec::new();
        let measure_cli = matches!((root_count, candidate_count), (1, 8192) | (8 | 64, 1024));
        let candidates: Vec<_> = rows.values().map(|row| row.candidate.clone()).collect();
        let aggregates: Vec<_> = rows
            .values()
            .map(|row| row.directory_aggregate().unwrap().clone())
            .collect();
        let mut cli_legacy = Vec::new();
        let mut cli_grouped = Vec::new();
        if measure_cli {
            assert_eq!(
                legacy_cli_candidates(&roots, &candidates, &aggregates),
                grouped_cli_candidates(&roots, &candidates, &aggregates),
            );
        }
        for repetition in 0..3 {
            // Alternate old/new ordering; retain every predeclared repetition, including
            // slow samples. This is a phase comparison, not a scan or tail-latency claim.
            assert!(
                started.elapsed() < Duration::from_secs(900),
                "bounded benchmark deadline"
            );
            let candidate_old = || legacy_candidates(&roots, &rows);
            let candidate_new = || grouped_candidates(&roots, &rows);
            let indexes_old = || {
                roots
                    .iter()
                    .map(|root| {
                        legacy_index(root, &roots, &fixture.scanned.covered_paths, &listings)
                    })
                    .collect::<Vec<_>>()
            };
            let indexes_new = || grouped_indexes(&roots, &fixture.scanned.covered_paths, &listings);
            if repetition % 2 == 0 {
                candidate_legacy.push(elapsed_projection(candidate_old));
                candidate_grouped.push(elapsed_projection(candidate_new));
                index_legacy.push(elapsed_projection(indexes_old));
                index_grouped.push(elapsed_projection(indexes_new));
            } else {
                candidate_grouped.push(elapsed_projection(candidate_new));
                candidate_legacy.push(elapsed_projection(candidate_old));
                index_grouped.push(elapsed_projection(indexes_new));
                index_legacy.push(elapsed_projection(indexes_old));
            }
            if measure_cli {
                let old = || legacy_cli_candidates(&roots, &candidates, &aggregates);
                let new = || grouped_cli_candidates(&roots, &candidates, &aggregates);
                if repetition % 2 == 0 {
                    cli_legacy.push(elapsed_projection(old));
                    cli_grouped.push(elapsed_projection(new));
                } else {
                    cli_grouped.push(elapsed_projection(new));
                    cli_legacy.push(elapsed_projection(old));
                }
            }
        }
        println!(
            "CACHE_PREPARATION {}",
            serde_json::json!({
                "roots": root_count,
                "candidates": candidate_count,
                "listings": listings.len(),
                "repetitions": 3,
                "equivalent": true,
                "candidateLegacyNs": candidate_legacy,
                "candidateGroupedNs": candidate_grouped,
                "indexLegacyNs": index_legacy,
                "indexGroupedNs": index_grouped,
                "cliCandidateLegacyNs": cli_legacy,
                "cliCandidateGroupedNs": cli_grouped,
            })
        );
    }
    for row in fixture.rows.values() {
        assert_eq!(
            fs::read(row.observed_native_path().unwrap().join("payload")).unwrap(),
            b"12345678"
        );
    }
}
