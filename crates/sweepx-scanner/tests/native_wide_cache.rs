//! A native fan-out oracle keeps default traversal below the shared I/O allowance.
#![cfg(any(
    all(target_os = "linux", feature = "platform-linux"),
    all(target_os = "macos", feature = "platform-macos"),
    all(windows, feature = "platform-windows"),
))]

use sweepx_model::{ByteValue, DecimalU128};
use sweepx_platform::{CancellationToken, ScanRoot};
use sweepx_scanner::{HostPlatformScanner, Scanner, ScannerOptions};

#[derive(Clone, Debug, PartialEq, Eq)]
struct DirectoryOracle {
    logical_bytes: u128,
    direct_children: u128,
    recursive_entries: u128,
}

fn ordinary_facts(
    path: &std::path::Path,
    directories: &mut std::collections::BTreeMap<std::path::PathBuf, DirectoryOracle>,
    files: &mut std::collections::BTreeMap<std::path::PathBuf, u128>,
) -> DirectoryOracle {
    let mut facts = DirectoryOracle {
        logical_bytes: 0,
        direct_children: 0,
        recursive_entries: 0,
    };
    for child in std::fs::read_dir(path).unwrap() {
        let child = child.unwrap();
        let metadata = std::fs::symlink_metadata(child.path()).unwrap();
        facts.direct_children += 1;
        facts.recursive_entries += 1;
        if metadata.is_dir() {
            let child_facts = ordinary_facts(&child.path(), directories, files);
            facts.logical_bytes += child_facts.logical_bytes;
            facts.recursive_entries += child_facts.recursive_entries;
        } else if metadata.is_file() {
            let bytes = u128::from(metadata.len());
            facts.logical_bytes += bytes;
            files.insert(child.path(), bytes);
        }
    }
    directories.insert(path.to_path_buf(), facts.clone());
    facts
}

struct EveryDirectory;

impl sweepx_scanner::JunkClassifier for EveryDirectory {
    fn uses_only_local_markers(&self) -> bool {
        true
    }

    fn needs_file_marker(&self, _: &sweepx_model::NativeName) -> bool {
        false
    }

    fn classify(
        &self,
        _: &sweepx_model::ScannedEntry,
        _: &std::collections::BTreeMap<
            sweepx_model::ScanEntryId,
            std::collections::BTreeSet<String>,
        >,
    ) -> Option<String> {
        Some("benchmark-directory".into())
    }
}

/// Only this immutable fixture supplies the file oracle; the native backend must still confirm
/// each cached file's current type and length. This isolates the existing scanner cache path.
struct FixtureFiles(std::collections::BTreeMap<std::path::PathBuf, u128>);

impl sweepx_scanner::SubtreeReuse for FixtureFiles {
    fn plan_entries(
        &self,
        _: &std::path::Path,
        children: &[sweepx_platform::DirectoryEntryRecord],
    ) -> Option<Vec<sweepx_scanner::PlannedEntry>> {
        Some(
            children
                .iter()
                .map(|child| match self.0.get(&child.path) {
                    Some(bytes) => {
                        sweepx_scanner::PlannedEntry::ReuseFile(sweepx_platform::CachedFileEntry {
                            path: child.path.clone(),
                            file_name: child.file_name.clone(),
                            logical_bytes: *bytes,
                        })
                    }
                    None => sweepx_scanner::PlannedEntry::Inspect(child.clone()),
                })
                .collect(),
        )
    }
}

fn assert_directory_oracle(
    scan: &sweepx_scanner::ClassifiedScan,
    oracle: &std::collections::BTreeMap<std::path::PathBuf, DirectoryOracle>,
) {
    assert!(
        scan.summary.boundaries.is_empty(),
        "{:?}",
        scan.summary.boundaries
    );
    assert_eq!(scan.summary.error_count(), 0);
    let observed: std::collections::BTreeMap<_, _> = scan
        .summary
        .roots
        .iter()
        .chain(&scan.summary.entries)
        .map(|entry| {
            (
                entry.identity.as_ref().unwrap().entry_id.as_str(),
                std::path::PathBuf::from(&entry.display_path),
            )
        })
        .collect();
    assert_eq!(observed.len(), oracle.len());
    assert_eq!(scan.summary.aggregates.len(), oracle.len());
    for aggregate in &scan.summary.aggregates {
        let path = &observed[aggregate.directory_identity.as_str()];
        let facts = &oracle[path];
        assert!(aggregate.coverage.complete, "{}", path.display());
        assert_eq!(
            aggregate.apparent_logical_bytes,
            ByteValue::Known {
                value: DecimalU128(facts.logical_bytes)
            },
            "{}",
            path.display(),
        );
        assert_eq!(
            aggregate.direct_child_count,
            sweepx_model::CountValue::Known {
                value: DecimalU128(facts.direct_children)
            },
            "{}",
            path.display(),
        );
        assert_eq!(
            aggregate.recursive_entry_count,
            sweepx_model::CountValue::Known {
                value: DecimalU128(facts.recursive_entries)
            },
            "{}",
            path.display(),
        );
    }
}

#[test]
#[ignore = "opt-in release native scan benchmark with an ordinary walk oracle; no Trash"]
fn benchmark_native_cached_deep_tree() {
    let owner = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = owner.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    for shard in 0..32 {
        for branch in 0..4 {
            let directory = root.join(format!(
                "{shard:02x}/{branch:02x}/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"
            ));
            std::fs::create_dir_all(&directory).unwrap();
            for file in 0..256 {
                std::fs::write(directory.join(format!("payload-{file:03}")), [0u8; 37]).unwrap();
            }
        }
    }
    let mut oracle = std::collections::BTreeMap::new();
    let mut files = std::collections::BTreeMap::new();
    ordinary_facts(&root, &mut oracle, &mut files);
    let fixture = FixtureFiles(files);
    let scanner = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default());
    let no_file_index = Scanner::new(
        HostPlatformScanner::new(),
        ScannerOptions {
            retain_file_index: false,
            ..Default::default()
        },
    );
    let roots = [ScanRoot::new(root).unwrap()];
    // The ordinary walk and initial scan warm the OS cache. Timings cover only Scanner's full
    // classified walk and result assembly; assertion/drop time is excluded. Cache reuse below
    // is the logical-file shortcut, not FSEvents preparation or a whole junk session.
    let initial = scanner
        .scan_classified(&roots, &CancellationToken::new(), &EveryDirectory, None)
        .unwrap();
    assert_directory_oracle(&initial, &oracle);
    drop(initial);
    for repetition in 0..5 {
        for (mode, scanner, reuse) in [
            ("os_warm", &scanner, None),
            (
                "logical_file_cache",
                &scanner,
                Some(&fixture as &dyn sweepx_scanner::SubtreeReuse),
            ),
            ("without_file_index", &no_file_index, None),
        ] {
            let started = std::time::Instant::now();
            let scan = scanner
                .scan_classified(&roots, &CancellationToken::new(), &EveryDirectory, reuse)
                .unwrap();
            let elapsed_micros = started.elapsed().as_micros();
            assert_directory_oracle(&scan, &oracle);
            println!(
                "{{\"mode\":\"{mode}\",\"repetition\":{repetition},\"elapsed_micros\":{elapsed_micros},\"os\":\"{}\",\"arch\":\"{}\",\"debug_assertions\":{},\"directories\":{},\"files\":{},\"oracle_equal\":true}}",
                std::env::consts::OS,
                std::env::consts::ARCH,
                cfg!(debug_assertions),
                oracle.len(),
                fixture.0.len(),
            );
        }
    }
}

fn ordinary_total(path: &std::path::Path) -> u128 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                ordinary_total(&entry.path())
            } else if metadata.is_file() {
                u128::from(metadata.len())
            } else {
                0
            }
        })
        .sum()
}

#[test]
fn default_native_scan_completes_wide_cache_with_independent_totals() {
    let owner = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = owner.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    // Two wide levels overflow a 256-handle process allowance if a scanner opens
    // every sibling before descending. Expected bytes come from ordinary metadata.
    for shard in 0..256 {
        for child in 0..4 {
            let directory = root.join(format!("{shard:02x}/{child:02x}/a/b/c/d/e/f/g/h"));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("payload"), [0u8; 37]).unwrap();
        }
    }
    let expected = ordinary_total(&root);
    let scan = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
        .unwrap();
    assert!(scan.boundaries.is_empty(), "{:?}", scan.boundaries);
    assert_eq!(scan.error_count(), 0);
    let root_id = &scan.roots[0].identity.as_ref().unwrap().entry_id;
    let aggregate = scan
        .aggregates
        .iter()
        .find(|row| row.directory_identity == root_id.as_str())
        .unwrap();
    assert!(aggregate.coverage.complete);
    assert_eq!(
        aggregate.apparent_logical_bytes,
        ByteValue::Known {
            value: DecimalU128(expected)
        }
    );
}

#[test]
fn detail_byte_limit_keeps_independently_measured_recursive_totals() {
    let owner = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = owner.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    for branch in 0..8 {
        let directory = root.join(format!("branch-{branch}/a/b/c/d/e/f/g/h"));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("payload"), [0u8; 37]).unwrap();
    }
    let expected = ordinary_total(&root);
    // Native identity recipes amplify deep rows. Exhausting a small detail allowance must
    // still enumerate every directory and count payloads; the limit is not a traversal cap.
    let scan = Scanner::new(
        HostPlatformScanner::new(),
        ScannerOptions {
            resource_limits: sweepx_platform::ScanResourceLimits {
                max_retained_entry_bytes: 4096,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
    .unwrap();
    assert_eq!(scan.error_count(), 0);
    assert!(
        scan.boundaries
            .iter()
            .any(|boundary| { boundary.detail == "retained entry byte budget exceeded" })
    );
    assert!(scan.entries.len() < 8 * 10);
    let root_id = &scan.roots[0].identity.as_ref().unwrap().entry_id;
    let aggregate = scan
        .aggregates
        .iter()
        .find(|row| row.directory_identity == root_id.as_str())
        .unwrap();
    assert!(aggregate.coverage.complete);
    assert_eq!(
        aggregate.apparent_logical_bytes,
        ByteValue::Known {
            value: DecimalU128(expected)
        }
    );
}
