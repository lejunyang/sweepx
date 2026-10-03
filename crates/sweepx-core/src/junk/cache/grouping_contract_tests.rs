//! Independent native fixtures for optional cache-publication attribution.

use super::*;
use crate::junk::JunkService;
use crate::junk::git::native_path;
use crate::junk::session::{JunkSessionCandidate, JunkSessionFacts};
use std::collections::BTreeSet;
use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use sweepx_platform::{CancellationToken, ScanRoot};
use sweepx_scanner::{ClassifiedScan, HostPlatformScanner, Scanner, ScannerOptions};

struct NativeFixture {
    _guard: tempfile::TempDir,
    base: PathBuf,
    roots: Vec<PathBuf>,
}

impl NativeFixture {
    fn new() -> Self {
        let guard = tempfile::tempdir().unwrap();
        // Native APIs reject linked ancestors; /var is a host-created alias on macOS.
        let base = fs::canonicalize(guard.path()).unwrap();
        let parent = base.join("root");
        let nested = parent.join("nested");
        let deep = nested.join("deep");
        let neighbor = base.join("root-extra");
        for root in [&parent, &nested, &deep, &neighbor] {
            fs::create_dir_all(root.join("target")).unwrap();
            fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
            fs::write(root.join("target/payload"), b"native fixture bytes").unwrap();
        }
        // Deliberately scramble depth order: input order cannot stand in for attribution.
        Self {
            _guard: guard,
            base,
            roots: vec![deep, parent, neighbor, nested],
        }
    }

    fn scan(&self) -> ClassifiedScan {
        Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
            .scan_classified(
                &self
                    .roots
                    .iter()
                    .map(|root| ScanRoot::new(root.clone()).unwrap())
                    .collect::<Vec<_>>(),
                &CancellationToken::new(),
                &JunkService::built_in().unwrap(),
                None,
            )
            .unwrap()
    }

    fn expected_candidates(&self) -> BTreeMap<usize, BTreeSet<PathBuf>> {
        // This fixture has exactly one structural project candidate per independently named root.
        BTreeMap::from([
            (0, BTreeSet::from([self.roots[0].join("target")])),
            (1, BTreeSet::from([self.roots[1].join("target")])),
            (2, BTreeSet::from([self.roots[2].join("target")])),
            (3, BTreeSet::from([self.roots[3].join("target")])),
        ])
    }

    fn expected_listings(&self) -> BTreeMap<usize, BTreeSet<PathBuf>> {
        BTreeMap::from([
            (
                0,
                BTreeSet::from([self.roots[0].clone(), self.roots[0].join("target")]),
            ),
            (
                1,
                BTreeSet::from([self.roots[1].clone(), self.roots[1].join("target")]),
            ),
            (
                2,
                BTreeSet::from([self.roots[2].clone(), self.roots[2].join("target")]),
            ),
            (
                3,
                BTreeSet::from([self.roots[3].clone(), self.roots[3].join("target")]),
            ),
        ])
    }
}

fn candidate_rows(scan: &ClassifiedScan) -> Vec<Arc<JunkSessionCandidate>> {
    let service = JunkService::built_in().unwrap();
    let aggregates: BTreeMap<_, _> = scan
        .summary
        .aggregates
        .iter()
        .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
        .collect();
    scan.summary
        .roots
        .iter()
        .chain(&scan.summary.entries)
        .filter_map(|entry| {
            let id = &entry.validated_identity().unwrap()?.entry_id;
            let decision = scan.decisions.get(id)?;
            let candidate = service.interpret(
                decision,
                entry,
                &aggregates,
                &[],
                &crate::junk::platform::PlatformJunkEvidence::default(),
            )?;
            let aggregate = aggregates[id.as_str()];
            Some(Arc::new(JunkSessionCandidate {
                candidate,
                facts: JunkSessionFacts::Directory(Box::new(aggregate.clone())),
            }))
        })
        .collect()
}

fn ordinary_file_lengths(path: &Path) -> BTreeMap<String, u128> {
    // Ordinary native metadata is an independent oracle, including host-created regular files.
    fs::read_dir(path)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            metadata.file_type().is_file().then(|| {
                (
                    entry.file_name().into_string().unwrap(),
                    u128::from(metadata.len()),
                )
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn cache_file_snapshot(cache: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    if !cache.exists() {
        return files;
    }
    let mut pending = vec![cache.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let kind = fs::symlink_metadata(&path).unwrap().file_type();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                pending.push(path);
            } else {
                assert!(kind.is_file());
                files.insert(
                    path.strip_prefix(cache).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    files
}

fn listing_paths(
    groups: &RootGroups<(&String, &sweepx_scanner::DirListing)>,
    root_count: usize,
) -> BTreeMap<usize, BTreeSet<PathBuf>> {
    (0..root_count)
        .map(|owner| {
            (
                owner,
                groups
                    .get(owner)
                    .iter()
                    .map(|(path, _)| PathBuf::from(path.as_str()))
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn deepest_component_root_and_last_equal_root_own_the_path() {
    let roots = vec![
        PathBuf::from("/scope/project/deep"),
        PathBuf::from("/scope"),
        PathBuf::from("/scope/project"),
        PathBuf::from("/scope/project"),
    ];
    let mut budget = GroupingBudget::new(64 * 1024);
    let scope = RootScope::new(&roots, &mut budget).unwrap();
    for (path, owner) in [
        ("/scope", Some(1)),
        ("/scope/root-file", Some(1)),
        ("/scope/project", Some(3)),
        ("/scope/project/target", Some(3)),
        ("/scope/project/deep/target", Some(0)),
        ("/scope/project/deeper/target", Some(3)),
        ("/scope-other/target", None),
        ("/outside", None),
    ] {
        assert_eq!(scope.owner_index(Path::new(path)), owner, "{path}");
    }
}

#[test]
fn observed_sources_require_exact_native_roots_and_fill_only_the_last_duplicate() {
    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let rows = candidate_rows(&scan);
    let candidate = rows[0].candidate.source_entry.as_ref().unwrap().clone();
    let mut missing_locator = scan.observed_roots[0].clone();
    missing_locator.native_locator = None;
    missing_locator.display_path = fixture.roots[1].display().to_string();
    let mut sources = vec![candidate, missing_locator];
    sources.extend(scan.observed_roots.clone());
    let mut roots = fixture.roots.clone();
    roots.push(fixture.roots[1].clone());
    let mut budget = GroupingBudget::new(1024 * 1024);
    let scope = RootScope::new(&roots, &mut budget).unwrap();
    let groups = group_sources(&scope, &sources, &mut budget, &CancellationToken::new()).unwrap();
    assert!(groups.get(1).is_empty());
    for ordinal in [0, 2, 3, 4] {
        let first_native_match = sources
            .iter()
            .find(|entry| native_path(entry).as_deref() == Some(roots[ordinal].as_path()))
            .unwrap();
        assert_eq!(groups.get(ordinal).len(), 1);
        assert!(std::ptr::eq(groups.get(ordinal)[0], first_native_match));
    }
    assert!(
        group_sources(
            &scope,
            &sources,
            &mut GroupingBudget::new(0),
            &CancellationToken::new(),
        )
        .is_none()
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(group_sources(&scope, &sources, &mut budget, &cancel).is_none());
}

#[test]
fn native_listing_groups_match_handwritten_ownership_and_ordinary_metadata() {
    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let mut budget = GroupingBudget::new(1024 * 1024);
    let scope = RootScope::new(&fixture.roots, &mut budget).unwrap();
    let groups = group_listings(
        &scope,
        &scan.covered_paths,
        &scan.dir_listings,
        &mut budget,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(
        listing_paths(&groups, fixture.roots.len()),
        fixture.expected_listings()
    );
    for owner in 0..fixture.roots.len() {
        let rows = groups.get(owner);
        assert!(rows.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for (path, listing) in rows {
            assert_eq!(listing.files, ordinary_file_lengths(Path::new(path)));
        }
    }
    assert!(budget.used_bytes() <= 1024 * 1024);
}

#[test]
fn grouping_declines_uncovered_missing_and_out_of_scope_listings() {
    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let mut covered = scan.covered_paths.clone();
    let mut listings = scan.dir_listings.clone();
    covered.insert(fixture.roots[3].join("target").display().to_string(), false);
    covered.remove(fixture.roots[0].to_str().unwrap());
    let unrelated = fixture.base.join("unrequested").display().to_string();
    covered.insert(unrelated.clone(), true);
    listings.insert(unrelated, sweepx_scanner::DirListing::default());
    let mut budget = GroupingBudget::new(1024 * 1024);
    let scope = RootScope::new(&fixture.roots, &mut budget).unwrap();
    let groups = group_listings(
        &scope,
        &covered,
        &listings,
        &mut budget,
        &CancellationToken::new(),
    )
    .unwrap();
    let expected = BTreeMap::from([
        (0, BTreeSet::from([fixture.roots[0].join("target")])),
        (
            1,
            BTreeSet::from([fixture.roots[1].clone(), fixture.roots[1].join("target")]),
        ),
        (
            2,
            BTreeSet::from([fixture.roots[2].clone(), fixture.roots[2].join("target")]),
        ),
        (3, BTreeSet::from([fixture.roots[3].clone()])),
    ]);
    assert_eq!(listing_paths(&groups, fixture.roots.len()), expected);
}

#[test]
fn candidate_paths_come_from_native_locators_despite_divergent_display_paths() {
    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let mut rows = candidate_rows(&scan);
    assert!(!rows.is_empty());
    for row in &mut rows {
        let row = Arc::make_mut(row);
        row.candidate.path = fixture.roots[2]
            .join("invented-display")
            .display()
            .to_string();
        row.candidate.source_entry.as_mut().unwrap().display_path = row.candidate.path.clone();
    }
    let mut budget = GroupingBudget::new(1024 * 1024);
    let scope = RootScope::new(&fixture.roots, &mut budget).unwrap();
    let mut decoded = 0;
    let grouped = group_native(
        &scope,
        rows.iter().map(Arc::as_ref),
        |row| {
            decoded += 1;
            row.observed_native_path()
        },
        None,
        &mut budget,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(decoded, rows.len());
    let actual: BTreeMap<_, _> = (0..fixture.roots.len())
        .map(|owner| {
            (
                owner,
                grouped
                    .get(owner)
                    .iter()
                    .map(|row| row.observed_native_path().unwrap())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(actual, fixture.expected_candidates());
    let candidates: Vec<_> = rows.iter().map(|row| row.candidate.clone()).collect();
    let prepared = super::super::publication::CandidateCacheGroups::prepare(
        &fixture.roots,
        &candidates,
        &scan.summary.aggregates,
        &CancellationToken::new(),
    )
    .unwrap();
    let mut published_paths = BTreeMap::new();
    for owner in 0..fixture.roots.len() {
        let projected = prepared
            .project_root(owner, &CancellationToken::new())
            .unwrap();
        for row in &projected {
            assert_eq!(
                row.aggregate.as_ref(),
                scan.summary
                    .aggregates
                    .iter()
                    .find(|aggregate| aggregate.directory_identity == row.entry_id.as_str())
            );
        }
        published_paths.insert(
            owner,
            projected
                .iter()
                .map(|row| native_path(row.source_entry.as_ref().unwrap()).unwrap())
                .collect(),
        );
    }
    assert_eq!(published_paths, fixture.expected_candidates());
    assert!(
        prepared
            .project_root(fixture.roots.len(), &CancellationToken::new())
            .is_err()
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(prepared.project_root(0, &cancelled).is_err());
    assert!(
        super::super::publication::CandidateCacheGroups::prepare(
            &fixture.roots,
            &candidates,
            &scan.summary.aggregates,
            &cancelled,
        )
        .is_err()
    );
    let source = rows[0].candidate.source_entry.as_ref().unwrap();
    assert_ne!(
        native_path(source).unwrap().display().to_string(),
        source.display_path
    );
    let mut missing = rows[0].as_ref().clone();
    missing
        .candidate
        .source_entry
        .as_mut()
        .unwrap()
        .native_locator = None;
    assert!(missing.observed_native_path().is_none());
    let mut incomplete = candidates;
    incomplete.push(missing.candidate.clone());
    assert!(
        super::super::publication::CandidateCacheGroups::prepare(
            &fixture.roots,
            &incomplete,
            &scan.summary.aggregates,
            &CancellationToken::new(),
        )
        .is_err()
    );
    assert!(
        group_native(
            &scope,
            std::iter::once(&missing).chain(rows.iter().map(Arc::as_ref)),
            |row| row.observed_native_path(),
            None,
            &mut budget,
            &CancellationToken::new(),
        )
        .is_none()
    );
}

#[test]
fn native_non_utf8_aliases_remain_distinct_for_attribution() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let rows = candidate_rows(&scan);
    let source = rows
        .iter()
        .find(|row| {
            row.observed_native_path() == Some(fixture.roots[3].join("target"))
                && row
                    .candidate
                    .source_entry
                    .as_ref()
                    .unwrap()
                    .native_locator
                    .as_ref()
                    .unwrap()
                    .parent_reopen_recipe
                    .len()
                    > 1
        })
        .unwrap();
    let mut paths = Vec::new();
    for byte in [0xfe, 0xff] {
        let mut row = source.as_ref().clone();
        // This host rejects malformed UTF-8 filesystem names. Keep real identity evidence but
        // vary one non-root native name to test the path codec only, with no reopen or action.
        let locator = row
            .candidate
            .source_entry
            .as_mut()
            .unwrap()
            .native_locator
            .as_mut()
            .unwrap();
        locator
            .parent_reopen_recipe
            .last_mut()
            .unwrap()
            .native_basename = sweepx_model::NativeName::UnixBytes(vec![b'n', byte]);
        paths.push(row.observed_native_path().unwrap());
    }
    assert_eq!(paths[0].to_string_lossy(), paths[1].to_string_lossy());
    assert_ne!(paths[0], paths[1]);
    let roots = vec![
        fixture.roots[1].join(OsString::from_vec(vec![b'n', 0xfe])),
        fixture.roots[1].join(OsString::from_vec(vec![b'n', 0xff])),
    ];
    let mut budget = GroupingBudget::new(64 * 1024);
    let scope = RootScope::new(&roots, &mut budget).unwrap();
    assert_eq!(scope.owner_index(&paths[0]), Some(0));
    assert_eq!(scope.owner_index(&paths[1]), Some(1));
    assert_eq!(scope.owner_index(&fixture.roots[3].join("target")), None);
}

#[test]
#[cfg(target_os = "macos")]
fn selected_scan_preserves_original_root_ownership_and_excludes_shallow_ancestors() {
    struct Observer;
    impl sweepx_scanner::ClassifiedScanObserver for Observer {}

    let fixture = NativeFixture::new();
    let selected = fixture.roots[1].join("target");
    let scan = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan_classified_subtrees_with_observer(
            &fixture
                .roots
                .iter()
                .map(|root| ScanRoot::new(root.clone()).unwrap())
                .collect::<Vec<_>>(),
            &CancellationToken::new(),
            &JunkService::built_in().unwrap(),
            None,
            std::slice::from_ref(&selected),
            &mut Observer,
        )
        .unwrap();
    assert_eq!(scan.subtree_coverage_complete, Some(true));
    let mut budget = GroupingBudget::new(1024 * 1024);
    let scope = RootScope::new(&fixture.roots, &mut budget).unwrap();
    let groups = group_listings(
        &scope,
        &scan.covered_paths,
        &scan.dir_listings,
        &mut budget,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(
        listing_paths(&groups, fixture.roots.len()),
        BTreeMap::from([
            (0, BTreeSet::new()),
            (1, BTreeSet::from([selected.clone()])),
            (2, BTreeSet::new()),
            (3, BTreeSet::new()),
        ])
    );
    let index = super::super::StoredSubtreeIndex::capture_owned(
        &fixture.roots[1],
        42,
        groups.get(1).iter().copied(),
    )
    .unwrap();
    assert!(index.is_covered(selected.to_str().unwrap()));
    assert!(!index.is_covered(fixture.roots[1].to_str().unwrap()));
    assert!(!index.is_covered(fixture.roots[3].to_str().unwrap()));
    assert_eq!(
        index.listing(selected.to_str().unwrap()).unwrap().files,
        ordinary_file_lengths(&selected)
    );
}

#[test]
fn optional_grouping_omission_preserves_live_observations() {
    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let before = scan.summary.clone();
    let mut scope_budget = GroupingBudget::new(64 * 1024);
    let scope = RootScope::new(&fixture.roots, &mut scope_budget).unwrap();
    assert!(RootScope::new(&fixture.roots, &mut GroupingBudget::new(0)).is_none());
    assert!(RootGroups::<usize>::new(fixture.roots.len(), &mut GroupingBudget::new(0)).is_none());
    assert!(
        group_listings(
            &scope,
            &scan.covered_paths,
            &scan.dir_listings,
            &mut GroupingBudget::new(0),
            &CancellationToken::new(),
        )
        .is_none()
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(
        group_listings(
            &scope,
            &scan.covered_paths,
            &scan.dir_listings,
            &mut GroupingBudget::new(1024 * 1024),
            &cancel,
        )
        .is_none()
    );
    assert_eq!(scan.summary, before);
    let live_paths: BTreeSet<_> = candidate_rows(&scan)
        .iter()
        .map(|row| row.observed_native_path().unwrap())
        .collect();
    let expected: BTreeSet<_> = fixture
        .expected_candidates()
        .into_values()
        .flatten()
        .collect();
    assert_eq!(live_paths, expected);
    for (path, listing) in &scan.dir_listings {
        assert_eq!(listing.files, ordinary_file_lengths(Path::new(path)));
    }
}

#[test]
fn cancellation_after_one_candidate_rejects_the_whole_optional_projection() {
    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let rows = candidate_rows(&scan);
    assert!(rows.len() > 1);
    let cancel = CancellationToken::new();
    let seen = std::cell::Cell::new(0);
    let mut budget = GroupingBudget::new(1024 * 1024);
    let scope = RootScope::new(&fixture.roots, &mut budget).unwrap();
    let result = group_native(
        &scope,
        rows.iter().map(|row| {
            seen.set(seen.get() + 1);
            if seen.get() == 2 {
                cancel.cancel();
            }
            row.as_ref()
        }),
        |row| row.observed_native_path(),
        None,
        &mut budget,
        &cancel,
    );
    assert!(result.is_none());
    assert_eq!(seen.get(), 2);
    assert_eq!(
        rows.iter()
            .map(|row| row.observed_native_path().unwrap())
            .collect::<BTreeSet<_>>(),
        fixture
            .expected_candidates()
            .into_values()
            .flatten()
            .collect()
    );
}

#[test]
fn a_full_auxiliary_budget_refuses_growth_without_discarding_admitted_items() {
    let mut budget = GroupingBudget::new(1024);
    let mut groups = RootGroups::new(1, &mut budget).unwrap();
    let mut admitted = 0;
    for item in 0usize..10_000 {
        if !groups.push(0, item, &mut budget) {
            break;
        }
        admitted += 1;
    }
    assert!(admitted > 0 && admitted < 10_000);
    assert!(budget.used_bytes() <= 1024);
    assert_eq!(groups.get(0), (0..admitted).collect::<Vec<_>>());
    assert!(!groups.push(0, usize::MAX, &mut GroupingBudget::new(0)));
    assert_eq!(groups.get(0), (0..admitted).collect::<Vec<_>>());
}

#[test]
#[cfg(target_os = "macos")]
fn grouped_native_facts_do_not_authorize_publication_after_root_replacement() {
    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let parent = &fixture.roots[1];
    let source = scan
        .observed_roots
        .iter()
        .find(|entry| native_path(entry).as_deref() == Some(parent.as_path()))
        .unwrap();
    let mut budget = GroupingBudget::new(1024 * 1024);
    let scope = RootScope::new(&fixture.roots, &mut budget).unwrap();
    let groups = group_listings(
        &scope,
        &scan.covered_paths,
        &scan.dir_listings,
        &mut budget,
        &CancellationToken::new(),
    )
    .unwrap();
    let before =
        super::super::StoredSubtreeIndex::capture_owned(parent, 42, groups.get(1).iter().copied())
            .unwrap();
    assert!(before.matches_observed_root(source));
    let old_root = fixture.base.join("observed-root");
    fs::rename(parent, &old_root).unwrap();
    fs::create_dir(parent).unwrap();
    let after =
        super::super::StoredSubtreeIndex::capture_owned(parent, 42, groups.get(1).iter().copied())
            .unwrap();
    assert!(!after.matches_observed_root(source));
    assert_ne!(
        fs::symlink_metadata(parent).unwrap().ino(),
        fs::symlink_metadata(old_root).unwrap().ino()
    );
}

#[test]
#[cfg(target_os = "macos")]
fn batch_publication_preserves_disk_on_omission_cancel_and_root_replacement() {
    use super::super::CacheReader;
    use super::super::provider::SubtreeCacheProvider;

    let fixture = NativeFixture::new();
    let scan = fixture.scan();
    let cache = fixture.base.join("cache");
    // No stored roots means prepare_files has no historical cursor to query. This fixture
    // exercises current native publication without relying on FSEvents timing or permissions.
    let provider =
        SubtreeCacheProvider::prepare_files(&cache, &fixture.roots, CacheReader::new(&cache));
    let mut errors = Vec::new();
    provider.store_observed_indexes_with_budget(
        &scan.observed_roots,
        &fixture.roots,
        42,
        &scan.covered_paths,
        &scan.dir_listings,
        &CancellationToken::new(),
        0,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert_eq!(errors.as_slice(), std::slice::from_ref(&cache));
    assert!(!cache.exists());
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    errors.clear();
    provider.store_observed_indexes(
        &scan.observed_roots,
        &fixture.roots,
        42,
        &scan.covered_paths,
        &scan.dir_listings,
        &cancelled,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert!(errors.is_empty());
    assert!(!cache.exists());
    provider.store_observed_indexes(
        &scan.observed_roots,
        &fixture.roots,
        42,
        &scan.covered_paths,
        &scan.dir_listings,
        &CancellationToken::new(),
        |root, _| errors.push(root.to_path_buf()),
    );
    assert!(errors.is_empty());
    let expected = fixture.expected_listings();
    let mut reader = CacheReader::new(&cache);
    for (ordinal, root) in fixture.roots.iter().enumerate() {
        let index = reader.index(root).unwrap();
        assert_eq!(
            index
                .listings
                .keys()
                .map(|path| PathBuf::from(path.as_str()))
                .collect::<BTreeSet<_>>(),
            expected[&ordinal]
        );
        for path in &expected[&ordinal] {
            assert!(index.is_covered(path.to_str().unwrap()));
            assert_eq!(
                index.listing(path.to_str().unwrap()).unwrap().files,
                ordinary_file_lengths(path)
            );
        }
    }
    let saved = cache_file_snapshot(&cache);
    assert!(!saved.is_empty());
    provider.store_observed_indexes_with_budget(
        &[],
        &fixture.roots,
        99,
        &scan.covered_paths,
        &scan.dir_listings,
        &CancellationToken::new(),
        0,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert!(errors.is_empty());
    assert_eq!(cache_file_snapshot(&cache), saved);
    let rows = candidate_rows(&scan);
    let child = rows[0].candidate.source_entry.as_ref().unwrap();
    // Only a descendant locator was offered, so there is no root publication. The small
    // allowance admits root/source views but would refuse a full listing view if it were built.
    provider.store_observed_indexes_with_budget(
        std::slice::from_ref(child),
        &fixture.roots,
        99,
        &scan.covered_paths,
        &scan.dir_listings,
        &CancellationToken::new(),
        256,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert!(errors.is_empty());
    assert_eq!(cache_file_snapshot(&cache), saved);
    provider.store_observed_indexes_with_budget(
        &scan.observed_roots,
        &fixture.roots,
        99,
        &scan.covered_paths,
        &scan.dir_listings,
        &CancellationToken::new(),
        0,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert_eq!(errors.as_slice(), std::slice::from_ref(&cache));
    assert_eq!(cache_file_snapshot(&cache), saved);
    errors.clear();
    provider.store_observed_indexes(
        &scan.observed_roots,
        &fixture.roots,
        99,
        &scan.covered_paths,
        &scan.dir_listings,
        &cancelled,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert!(errors.is_empty());
    assert_eq!(cache_file_snapshot(&cache), saved);
    let parent = &fixture.roots[1];
    let source = scan
        .observed_roots
        .iter()
        .find(|source| native_path(source).as_deref() == Some(parent.as_path()))
        .unwrap();
    fs::rename(parent, fixture.base.join("original-root")).unwrap();
    fs::create_dir(parent).unwrap();
    provider.store_observed_indexes(
        std::slice::from_ref(source),
        std::slice::from_ref(parent),
        99,
        &scan.covered_paths,
        &scan.dir_listings,
        &CancellationToken::new(),
        |root, _| errors.push(root.to_path_buf()),
    );
    assert_eq!(errors.as_slice(), std::slice::from_ref(parent));
    assert_eq!(cache_file_snapshot(&cache), saved);
}

#[test]
#[cfg(target_os = "macos")]
fn single_root_batch_matches_direct_capture_with_a_small_auxiliary_allowance() {
    use super::super::provider::SubtreeCacheProvider;
    use super::super::{CacheReader, StoredSubtreeIndex};

    let fixture = NativeFixture::new();
    let root = &fixture.roots[1];
    let roots = std::slice::from_ref(root);
    let scan = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan_classified(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &JunkService::built_in().unwrap(),
            None,
        )
        .unwrap();
    let source = &scan.observed_roots[0];
    assert_eq!(native_path(source).as_deref(), Some(root.as_path()));
    // These omissions conservatively weaken real native observations. A present false root
    // still permits individually complete descendant file facts, without claiming root coverage.
    let mut covered = scan.covered_paths.clone();
    covered.insert(root.display().to_string(), false);
    covered.insert(root.join("nested").display().to_string(), false);
    covered.remove(fixture.roots[0].to_str().unwrap());
    let direct =
        StoredSubtreeIndex::capture(root, roots, 42, &covered, &scan.dir_listings).unwrap();
    assert!(direct.matches_observed_root(source));
    assert!(!direct.is_covered(root.to_str().unwrap()));
    assert!(!direct.is_covered(fixture.roots[0].to_str().unwrap()));
    assert!(!direct.is_covered(fixture.roots[3].to_str().unwrap()));
    for (path, listing) in &direct.listings {
        assert_eq!(listing.files, ordinary_file_lengths(Path::new(path)));
    }
    let cache = fixture.base.join("single-root-cache");
    let provider = SubtreeCacheProvider::prepare_files(&cache, roots, CacheReader::new(&cache));
    let mut errors = Vec::new();
    // One scope/source record fits this allowance; materializing the listing buckets does not.
    // The direct capture owns the separate per-root wire allowance and preserves its early stop.
    provider.store_observed_indexes_with_budget(
        &scan.observed_roots,
        roots,
        42,
        &covered,
        &scan.dir_listings,
        &CancellationToken::new(),
        64,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert!(errors.is_empty());
    assert_eq!(CacheReader::new(&cache).index(root).unwrap(), direct);
    let saved = cache_file_snapshot(&cache);
    provider.store_observed_indexes_with_budget(
        &scan.observed_roots,
        roots,
        99,
        &covered,
        &scan.dir_listings,
        &CancellationToken::new(),
        0,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert_eq!(errors.as_slice(), std::slice::from_ref(&cache));
    assert_eq!(cache_file_snapshot(&cache), saved);
    errors.clear();
    let mut missing_root = covered.clone();
    missing_root.remove(root.to_str().unwrap());
    provider.store_observed_indexes_with_budget(
        &scan.observed_roots,
        roots,
        99,
        &missing_root,
        &scan.dir_listings,
        &CancellationToken::new(),
        64,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert!(errors.is_empty());
    assert_eq!(cache_file_snapshot(&cache), saved);
    fs::rename(root, fixture.base.join("single-root-original")).unwrap();
    fs::create_dir(root).unwrap();
    provider.store_observed_indexes_with_budget(
        &scan.observed_roots,
        roots,
        99,
        &covered,
        &scan.dir_listings,
        &CancellationToken::new(),
        64,
        |root, _| errors.push(root.to_path_buf()),
    );
    assert_eq!(errors.as_slice(), std::slice::from_ref(root));
    assert_eq!(cache_file_snapshot(&cache), saved);
}
