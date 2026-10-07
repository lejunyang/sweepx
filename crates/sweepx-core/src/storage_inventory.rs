//! Shared native directory totals for browser and tool-installation analyses.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;
use sweepx_model::{ByteValue, EvidenceValue, NativeName, ObjectType, ScanEntryId, ScannedEntry};
use sweepx_platform::{CancellationToken, ScanRoot};
use sweepx_scanner::{
    ClassifiedScanObserver, HostPlatformScanner, JunkClassifier, ProgressEvent, ScanSummary,
    Scanner, ScannerOptions,
};
// Classification here selects aggregation rows, not junk. One traversal provides the parent total
// and each immediate child's share, avoiding the old repeated walks and discarded failure flags.
struct DirectoryRows;
impl JunkClassifier for DirectoryRows {
    fn uses_only_local_markers(&self) -> bool {
        true
    }
    fn needs_file_marker(&self, _: &NativeName) -> bool {
        false
    }
    fn classify(
        &self,
        entry: &ScannedEntry,
        _: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        let id = entry.identity.as_ref()?;
        (entry.object_type == ObjectType::Directory
            && (id.parent_id.is_none() || id.parent_id.as_ref() == Some(&id.scan_root_id)))
        .then(|| "storage_inventory_observation".into())
    }
}
struct Deadline<'a> {
    until: Instant,
    cancel: &'a CancellationToken,
    caller_cancel: &'a CancellationToken,
}
impl ClassifiedScanObserver for Deadline<'_> {
    fn on_progress(&mut self, _: &Path, _: &ProgressEvent) {
        if self.caller_cancel.is_cancelled() || Instant::now() >= self.until {
            self.cancel.cancel();
        }
    }
}

pub(crate) fn observe_directories(
    path: &Path,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<ScanSummary, String> {
    observe_directories_with_cancel(path, cancel, cancel, deadline)
}
/// A total's deadline does not cancel the caller's independent project-reference discovery.
/// Caller cancellation is forwarded at scanner progress boundaries, alongside deadline checks.
pub(crate) fn observe_directories_isolated_deadline(
    path: &Path,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<ScanSummary, String> {
    let local = CancellationToken::new();
    if cancel.is_cancelled() || Instant::now() >= deadline {
        local.cancel();
    }
    observe_directories_with_cancel(path, &local, cancel, deadline)
}
fn observe_directories_with_cancel(
    path: &Path,
    cancel: &CancellationToken,
    caller_cancel: &CancellationToken,
    deadline: Instant,
) -> Result<ScanSummary, String> {
    let mut options = ScannerOptions::default();
    options.resource_limits.max_visited_entries = 2_000_000;
    options.resource_limits.max_retained_aggregates = 16_384;
    options.resource_limits.max_classified_metadata_bytes = 64 * 1024 * 1024;
    options.resource_limits.max_classified_root_metadata_bytes = 64 * 1024 * 1024;
    let root = ScanRoot::new(path.to_path_buf()).map_err(|e| e.to_string())?;
    Scanner::new(HostPlatformScanner::new(), options)
        .scan_classified_with_observer(
            &[root],
            cancel,
            &DirectoryRows,
            None,
            &mut Deadline {
                until: deadline,
                cancel,
                caller_cancel,
            },
        )
        .map(|s| s.summary)
        .map_err(|e| e.to_string())
}
pub(crate) fn entry_bytes(scan: &ScanSummary, entry: &ScannedEntry) -> (Option<u128>, bool) {
    let Some(id) = &entry.identity else {
        return (None, false);
    };
    let Some(aggregate) = scan
        .aggregates
        .iter()
        .find(|a| a.directory_identity == id.entry_id.as_str())
    else {
        return (None, false);
    };
    let value: &ByteValue = &aggregate.apparent_logical_bytes;
    match value {
        EvidenceValue::Known { value } => (
            Some(value.0),
            aggregate.coverage.complete && !aggregate.coverage.details_lost,
        ),
        EvidenceValue::LowerBound { value, .. } => (Some(value.0), false),
        _ => (None, false),
    }
}

// Reuse the scanner's directory revalidation, reconstructing the root identity only from its
// captured native locator. No display path is used to produce the reopening recipe.
pub(crate) fn revalidate_directory(
    entry: &ScannedEntry,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let identity = entry
        .validated_identity()
        .map_err(|e| e.to_string())?
        .ok_or("missing_identity")?;
    let locator = entry
        .executable_native_locator()
        .map_err(|e| e.to_string())?
        .ok_or("missing_locator")?;
    let root = sweepx_model::ScanObjectIdentity {
        entry_id: locator.scan_root.entry_id.clone(),
        scan_root_id: locator.scan_root.entry_id.clone(),
        parent_id: None,
        platform_file_identity: locator.scan_root.platform_file_identity.clone(),
        filesystem_object_domain_identity: locator
            .scan_root
            .filesystem_object_domain_identity
            .clone(),
        volume_or_mount_identity: locator.scan_root.volume_or_mount_identity.clone(),
    };
    sweepx_scanner::DetailRescanner::new(
        HostPlatformScanner::new(),
        sweepx_platform::ScanResourceLimits::default(),
    )
    .revalidate_directory(
        sweepx_scanner::DetailRescanRequest {
            source_scan_id: &entry.scan_id,
            source_root_identity: &root,
            source_directory_identity: identity,
            directory_locator: locator,
            revision: sweepx_model::DecimalU128::new(1),
            max_rows: 0,
        },
        cancel,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}
