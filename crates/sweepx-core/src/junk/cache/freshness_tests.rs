//! Current candidates must come from native traversal even when the event service lags.

use super::*;
use crate::junk::JunkService;
use crate::junk::cache::StoredJunkCandidate;
use sweepx_platform::{CancellationToken, ScanRoot};
use sweepx_scanner::{HostPlatformScanner, Scanner, ScannerOptions};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let guard = tempfile::tempdir().unwrap();
    let base = guard.path().canonicalize().unwrap();
    let root = base.join("project");
    fs::create_dir_all(root.join("target/deep")).unwrap();
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join("target/stable"), b"stable-data").unwrap();
    fs::write(root.join("target/deep/changing"), b"old-data").unwrap();
    (guard, root, base.join("cache"))
}

fn scan(root: &Path, reuse: Option<&SubtreeCacheProvider>) -> sweepx_scanner::ClassifiedScan {
    Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan_classified(
            &[ScanRoot::new(root.to_path_buf()).unwrap()],
            &CancellationToken::new(),
            &JunkService::built_in().unwrap(),
            reuse.map(|provider| provider as &dyn SubtreeReuse),
        )
        .unwrap()
}

fn candidates(
    scan: &sweepx_scanner::ClassifiedScan,
) -> BTreeMap<PathBuf, crate::junk::candidate::JunkCandidate> {
    let service = JunkService::built_in().unwrap();
    let aggregates = scan
        .summary
        .aggregates
        .iter()
        .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
        .collect();
    scan.summary
        .entries
        .iter()
        .filter_map(|entry| {
            let id = &entry.validated_identity().unwrap()?.entry_id;
            let candidate = service.interpret(
                scan.decisions.get(id)?,
                entry,
                &aggregates,
                &[],
                &Default::default(),
            )?;
            assert!(
                candidate
                    .entry_id
                    .belongs_to(&scan.observed_roots[0].scan_id)
            );
            Some((crate::junk::git::native_path(entry)?, candidate))
        })
        .collect()
}

fn seed(root: &Path, cache: &Path) {
    let cursor = crate::current_event_id();
    let observed = scan(root, None);
    let rows = candidates(&observed)
        .into_values()
        .map(|row| StoredJunkCandidate::from_candidate(&row))
        .collect();
    let record = StoredJunkRoot::capture(root, rows, cursor, [0; 32]).unwrap();
    junk_cache::write(cache, &record).unwrap();
    let index = StoredSubtreeIndex::capture(
        root,
        &[root.to_path_buf()],
        cursor,
        &observed.covered_paths,
        &observed.dir_listings,
    )
    .unwrap();
    junk_cache::write_subtree_index(cache, &index).unwrap();
}

fn empty_log() -> ChangeLog {
    ChangeLog {
        events: vec![],
        must_rescan: false,
    }
}

fn prepare(root: &Path, cache: &Path) -> SubtreeCacheProvider {
    // The completed write is deliberately absent from this frozen journal response.
    let (provider, current) = SubtreeCacheProvider::prepare_with_query(
        cache,
        &[root.to_path_buf()],
        Some(&[0; 32]),
        |_, _| Ok(empty_log()),
    );
    assert!(current[0].is_none());
    provider
}

fn ordinary_logical_bytes(path: &Path) -> u128 {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let stat = fs::symlink_metadata(&path).unwrap();
            if stat.is_dir() {
                ordinary_logical_bytes(&path)
            } else if stat.is_file() {
                u128::from(stat.len())
            } else {
                0
            }
        })
        .sum()
}

#[test]
fn delayed_history_cannot_hide_nested_length_changes_or_new_candidates() {
    let (_guard, root, cache) = fixture();
    seed(&root, &cache);
    fs::write(
        root.join("target/deep/changing"),
        b"changed-longer-native-data",
    )
    .unwrap();
    fs::create_dir_all(root.join("nested/target")).unwrap();
    fs::write(root.join("nested/Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join("nested/target/new"), b"new-data").unwrap();
    let provider = prepare(&root, &cache);
    let stable = sweepx_platform::DirectoryEntryRecord::from_parent_and_name(
        &root.join("target"),
        sweepx_model::NativeName::unix(b"stable".to_vec()),
    )
    .unwrap();
    assert!(
        matches!(
            provider
                .plan_entries(&root.join("target"), &[stable])
                .unwrap()[0],
            PlannedEntry::ReuseFile(_)
        ),
        "file acceleration remains available, with live confirmation in the scanner"
    );
    let current = candidates(&scan(&root, Some(&provider)));
    assert_eq!(
        current.len(),
        2,
        "new project output cannot be omitted by an old root report"
    );
    for (path, row) in current {
        assert_eq!(
            row.reclaimable,
            sweepx_platform::known_u128(ordinary_logical_bytes(&path))
        );
    }
    assert_eq!(
        junk_cache::CacheReader::new(&cache).historical_roots(&[root])[0]
            .as_ref()
            .unwrap()
            .candidates_len(),
        1,
        "the stored history really predates the new candidate"
    );
}

#[test]
fn delayed_history_cannot_preserve_a_removed_rule_marker() {
    let (_guard, root, cache) = fixture();
    seed(&root, &cache);
    fs::remove_file(root.join("Cargo.toml")).unwrap();
    let provider = prepare(&root, &cache);
    assert!(candidates(&scan(&root, Some(&provider))).is_empty());
    assert!(candidates(&scan(&root, None)).is_empty());
}

#[test]
fn delayed_history_cannot_turn_a_replaced_link_into_an_old_regular_file() {
    let (guard, root, cache) = fixture();
    seed(&root, &cache);
    let outside = guard.path().join("outside");
    fs::write(&outside, vec![42; 64 * 1024]).unwrap();
    let changed = root.join("target/deep/changing");
    fs::remove_file(&changed).unwrap();
    std::os::unix::fs::symlink(&outside, &changed).unwrap();
    let provider = prepare(&root, &cache);
    let accelerated = scan(&root, Some(&provider));
    let fresh = scan(&root, None);
    let accelerated_rows = candidates(&accelerated);
    let fresh_rows = candidates(&fresh);
    assert_eq!(
        accelerated_rows.keys().collect::<Vec<_>>(),
        fresh_rows.keys().collect::<Vec<_>>()
    );
    for (path, row) in &accelerated_rows {
        assert_eq!(row.reclaimable, fresh_rows[path].reclaimable);
        assert_ne!(
            row.reclaimable,
            sweepx_platform::known_u128(64 * 1024 + 11),
            "link target must not enter the total"
        );
    }
    assert_eq!(fs::metadata(outside).unwrap().len(), 64 * 1024);
}
