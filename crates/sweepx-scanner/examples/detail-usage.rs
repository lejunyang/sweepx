//! Read-only phase diagnostic for the directory browser's recursive usage scan.
//! Run with an absolute root and optionally `--full` to compare full descendant metadata.
use std::error::Error;
use std::path::PathBuf;
use std::time::Instant;
use sweepx_model::{DecimalU128, ScanId};
use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot};
use sweepx_scanner::{
    DetailEntryIdAllocator, DetailRescanRequest, DetailRescanner, HostPlatformScanner, Scanner,
    ScannerOptions,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().ok_or("expected absolute root [--full]")?);
    let full = args.next().is_some_and(|arg| arg == "--full");
    let cancel = CancellationToken::new();
    let scan_id = ScanId::new("detail-usage-diagnostic");
    let started = Instant::now();
    let summary = Scanner::new(
        HostPlatformScanner::new(),
        ScannerOptions {
            scan_id: scan_id.clone(),
            ..Default::default()
        },
    )
    .scan_roots_only(&[ScanRoot::new(root)?], &cancel)?;
    let admission_ms = started.elapsed().as_secs_f64() * 1000.0;
    let root = summary.roots.first().ok_or("root admission failed")?;
    let identity = root.validated_identity()?.ok_or("root identity missing")?;
    let request = DetailRescanRequest {
        source_scan_id: &scan_id,
        source_root_identity: identity,
        source_directory_identity: identity,
        directory_locator: root
            .executable_native_locator()?
            .ok_or("root locator missing")?,
        revision: DecimalU128::new(1),
        max_rows: 16_384,
    };
    let scanner = DetailRescanner::new(HostPlatformScanner::new(), ScanResourceLimits::default());
    let mut ids = DetailEntryIdAllocator::new(scan_id.clone())?;
    let mut native = 0;
    let mut updates = 0;
    let mut progress = |update: sweepx_scanner::DetailRescanProgress| {
        native = update.native_file_lengths;
        updates += 1;
    };
    let started = Instant::now();
    let result = if full {
        scanner.rescan_with_progress(request, &mut ids, &cancel, &mut progress)?
    } else {
        scanner.rescan_logical_with_progress(request, &mut ids, &cancel, &mut progress)?
    };
    println!(
        "mode={} admission_ms={admission_ms:.3} traversal_ms={:.3} native_lengths={native} updates={updates}",
        if full { "full" } else { "logical" },
        started.elapsed().as_secs_f64() * 1000.0
    );
    println!(
        "entries={:?} logical={:?} coverage={:?}",
        result.aggregate.recursive_entry_count,
        result.aggregate.apparent_logical_bytes,
        result.aggregate.coverage
    );
    for row in result.rows {
        println!("{} {:?}", row.display_path, row.logical_bytes);
    }
    Ok(())
}
