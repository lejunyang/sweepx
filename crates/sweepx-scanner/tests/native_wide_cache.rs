//! A native fan-out oracle keeps default traversal below the shared I/O allowance.
#![cfg(any(
    all(target_os = "linux", feature = "platform-linux"),
    all(target_os = "macos", feature = "platform-macos"),
    all(windows, feature = "platform-windows"),
))]

use sweepx_model::{ByteValue, DecimalU128};
use sweepx_platform::{CancellationToken, ScanRoot};
use sweepx_scanner::{HostPlatformScanner, Scanner, ScannerOptions};

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
