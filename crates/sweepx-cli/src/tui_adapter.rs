//! Frontend composition between the generic terminal browser and identity-bound scanner.
//!
//! Application workflows remain independent of terminal libraries; this adapter only translates
//! requests and results and retains scanner cancellation and authority checks.

use std::sync::Mutex;

use sweepx_core::{CancellationToken, ScanSummary};
#[cfg(test)]
use sweepx_model::{DecimalU128, ScanId};
use sweepx_scanner::{
    DetailEntryIdAllocator, DetailRescanError, DetailRescanRequest, DetailRescanner,
    HostPlatformScanner,
};
use sweepx_tui::{
    DetailRescanFailure as TuiDetailRescanFailure, DetailRescanProgress as TuiDetailRescanProgress,
    DetailRescanProvider, DetailRescanReason, DetailRescanRequest as TuiDetailRescanRequest,
    DetailRescanResult as TuiDetailRescanResult, RefreshedDetail,
};

/// A read-only adapter from the TUI detail protocol to the host scanner's targeted rescan API.
///
/// Construction fails closed when the live summary does not establish one consistent scan-id
/// namespace. The provider never accepts a display path as authority; scanner-side reopening is
/// driven exclusively by the request's lossless native root and no-follow lineage recipe.
pub(crate) struct TuiDetailRescanProvider {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    live: Option<LiveTuiDetailRescanProvider>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct LiveTuiDetailRescanProvider {
    scanner: DetailRescanner<HostPlatformScanner>,
    ids: Mutex<DetailEntryIdAllocator>,
    cancel: Mutex<CancellationToken>,
    progress: Mutex<Option<std::sync::mpsc::SyncSender<TuiDetailRescanProgress>>>,
}

/// Builds the frontend adapter; invalid scan identities leave it unavailable.
pub(crate) fn tui_detail_rescan_provider(summary: &ScanSummary) -> TuiDetailRescanProvider {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let live = live_tui_detail_rescan_provider(summary).ok();
        TuiDetailRescanProvider { live }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = summary;
        TuiDetailRescanProvider {}
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn live_tui_detail_rescan_provider(
    summary: &ScanSummary,
) -> Result<LiveTuiDetailRescanProvider, DetailRescanError> {
    let scan_id = summary
        .roots
        .iter()
        .chain(summary.entries.iter())
        .map(|entry| &entry.scan_id)
        .next()
        .ok_or(DetailRescanError::InvalidRequest)?
        .clone();
    let mut ids = DetailEntryIdAllocator::new(scan_id.clone())?;
    for entry in summary.roots.iter().chain(summary.entries.iter()) {
        if entry.scan_id != scan_id {
            return Err(DetailRescanError::InvalidRequest);
        }
        let identity = entry
            .validated_identity()
            .map_err(|_| DetailRescanError::InvalidRequest)?
            .ok_or(DetailRescanError::InvalidRequest)?;
        ids.reserve(&identity.entry_id)?;
        ids.reserve(&identity.scan_root_id)?;
        if let Some(parent_id) = &identity.parent_id {
            ids.reserve(parent_id)?;
        }
    }
    for aggregate in &summary.aggregates {
        if aggregate.scan_id != scan_id {
            return Err(DetailRescanError::InvalidRequest);
        }
        ids.reserve(
            &aggregate
                .scan_entry_id()
                .map_err(|_| DetailRescanError::InvalidRequest)?,
        )?;
    }
    Ok(LiveTuiDetailRescanProvider {
        scanner: DetailRescanner::new(
            HostPlatformScanner::new(),
            sweepx_platform::ScanResourceLimits::default(),
        ),
        ids: Mutex::new(ids),
        cancel: Mutex::new(CancellationToken::new()),
        progress: Mutex::new(None),
    })
}

impl DetailRescanProvider for TuiDetailRescanProvider {
    fn set_progress_sink(
        &self,
        sink: Option<std::sync::mpsc::SyncSender<TuiDetailRescanProgress>>,
    ) {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if let Some(live) = &self.live
            && let Ok(mut progress) = live.progress.lock()
        {
            *progress = sink;
        }
    }

    fn prepare_detail_rescan(&self) {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if let Some(live) = &self.live
            && let Ok(mut cancel) = live.cancel.lock()
        {
            *cancel = CancellationToken::new();
        }
    }

    fn rescan_detail(&self, request: &TuiDetailRescanRequest) -> TuiDetailRescanResult {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if let Some(live) = &self.live {
            let binding = request.binding.clone();
            let Ok(cancel_slot) = live.cancel.lock() else {
                return TuiDetailRescanResult::Failed {
                    binding: Box::new(binding),
                    failure: TuiDetailRescanFailure::Unavailable,
                };
            };
            let cancel = cancel_slot.clone();
            drop(cancel_slot);
            let Ok(mut ids) = live.ids.lock() else {
                return TuiDetailRescanResult::Failed {
                    binding: Box::new(binding),
                    failure: TuiDetailRescanFailure::Unavailable,
                };
            };
            let scanner_request = DetailRescanRequest {
                source_scan_id: &request.binding.source_scan_id,
                source_root_identity: &request.binding.source_root_identity,
                source_directory_identity: &request.binding.source_directory_identity,
                directory_locator: &request.directory_locator,
                revision: request.binding.revision,
                max_rows: request.max_rows,
            };
            let scanned = if request.reason == DetailRescanReason::ProgressiveListing {
                live.scanner
                    .rescan_direct_children(scanner_request, &mut ids, &cancel)
            } else if request.reason == DetailRescanReason::ProgressiveAggregate {
                live.scanner
                    .rescan_with_progress(scanner_request, &mut ids, &cancel, |progress| {
                        let Some(sender) = live.progress.lock().ok().and_then(|slot| slot.clone())
                        else {
                            return;
                        };
                        // UI progress is lossy by design. A full queue means the terminal has a
                        // newer-enough lower bound pending; the final result remains authoritative.
                        let _ = sender.try_send(TuiDetailRescanProgress {
                            binding: binding.clone(),
                            row: progress.row,
                            aggregate: progress.aggregate,
                        });
                    })
            } else {
                live.scanner.rescan(scanner_request, &mut ids, &cancel)
            };
            let result = match scanned {
                Ok(detail) => TuiDetailRescanResult::Refreshed(Box::new(RefreshedDetail {
                    binding,
                    observed_root: detail.observed_root,
                    observed_directory: detail.observed_directory,
                    rows: detail.rows,
                    aggregate: detail.aggregate,
                })),
                Err(error) => TuiDetailRescanResult::Failed {
                    binding: Box::new(binding),
                    failure: map_tui_detail_rescan_error(error),
                },
            };
            return result;
        }
        TuiDetailRescanResult::Failed {
            binding: Box::new(request.binding.clone()),
            failure: TuiDetailRescanFailure::Unavailable,
        }
    }

    fn cancel_detail_rescan(&self) {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if let Some(live) = &self.live
            && let Ok(cancel) = live.cancel.lock()
        {
            cancel.cancel();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn map_tui_detail_rescan_error(error: DetailRescanError) -> TuiDetailRescanFailure {
    match error {
        DetailRescanError::InvalidRequest => TuiDetailRescanFailure::InvalidResult,
        DetailRescanError::IdentityUnavailable => TuiDetailRescanFailure::IdentityUnavailable,
        DetailRescanError::IdentityMismatch => TuiDetailRescanFailure::IdentityMismatch,
        DetailRescanError::MountChanged => TuiDetailRescanFailure::MountChanged,
        DetailRescanError::SymlinkOrReparse => TuiDetailRescanFailure::SymlinkOrReparse,
        DetailRescanError::Cancelled => TuiDetailRescanFailure::Cancelled,
        DetailRescanError::ResourceLimit => TuiDetailRescanFailure::ResourceLimit,
        DetailRescanError::Unavailable => TuiDetailRescanFailure::Unavailable,
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod tui_detail_rescan_provider_tests {
    use super::*;
    use sweepx_core::{CoreContext, MemorySnapshotStore, ScanRequest, scan_with_store};
    use sweepx_i18n::{Locale, LocaleResolution};
    use sweepx_model::{
        FilesystemObjectDomainIdentity, IdentityEvidence, NativeAbsolutePath, NativeName,
        NativePathComponent, ObjectType, PlatformFileIdentity, ScanEntryId, ScanObjectIdentity,
        VolumeOrMountIdentity,
    };
    use sweepx_tui::{DetailRescanBinding, DetailRescanReason};

    fn encoded_name(name: &std::ffi::OsStr) -> String {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            NativeName::unix(name.as_bytes()).encoded_value()
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            NativeName::windows_utf16(name.encode_wide().collect::<Vec<_>>()).encoded_value()
        }
    }

    fn identity(scan_id: &ScanId, ordinal: u128) -> ScanObjectIdentity {
        let entry_id = ScanEntryId::for_scan_ordinal(scan_id, ordinal).unwrap();
        ScanObjectIdentity {
            entry_id: entry_id.clone(),
            scan_root_id: entry_id,
            parent_id: None,
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(1),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(1),
            }),
        }
    }

    #[test]
    fn empty_summary_constructs_a_fail_closed_unavailable_provider() {
        let scan_id = ScanId::new("missing-live-summary");
        let identity = identity(&scan_id, 1);
        let component = NativePathComponent {
            entry_id: identity.entry_id.clone(),
            parent_id: None,
            native_basename: {
                #[cfg(unix)]
                {
                    NativeName::unix(b"root".to_vec())
                }
                #[cfg(windows)]
                {
                    NativeName::windows_utf16("root".encode_utf16().collect::<Vec<_>>())
                }
            },
            object_type: ObjectType::Directory,
            platform_file_identity: identity.platform_file_identity.clone(),
            filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
            metadata_fingerprint: "root".to_string(),
        };
        let locator = sweepx_model::NativeLocatorEvidence {
            scan_root: component.clone(),
            scan_root_absolute_path: Some({
                #[cfg(unix)]
                {
                    NativeAbsolutePath::unix(b"/root".to_vec())
                }
                #[cfg(windows)]
                {
                    NativeAbsolutePath::windows_utf16(r"C:\root".encode_utf16().collect::<Vec<_>>())
                }
            }),
            parent_reopen_recipe: Vec::new(),
            entry: component,
        };
        let provider = tui_detail_rescan_provider(&ScanSummary {
            roots: Vec::new(),
            entries: Vec::new(),
            aggregates: Vec::new(),
            boundaries: Vec::new(),
            progress: Vec::new(),
        });
        let request = TuiDetailRescanRequest {
            binding: DetailRescanBinding {
                source_scan_id: scan_id,
                source_root_identity: identity.clone(),
                source_directory_identity: identity,
                base_revision: DecimalU128::new(1),
                revision: DecimalU128::new(2),
            },
            directory_locator: locator,
            reason: DetailRescanReason::Incomplete,
            max_rows: 1,
        };

        assert!(matches!(
            provider.rescan_detail(&request),
            TuiDetailRescanResult::Failed { binding, failure: TuiDetailRescanFailure::Unavailable }
                if *binding == request.binding
        ));
    }

    #[test]
    fn scanner_error_mapping_is_conservative() {
        let cases = [
            (
                DetailRescanError::InvalidRequest,
                TuiDetailRescanFailure::InvalidResult,
            ),
            (
                DetailRescanError::IdentityUnavailable,
                TuiDetailRescanFailure::IdentityUnavailable,
            ),
            (
                DetailRescanError::IdentityMismatch,
                TuiDetailRescanFailure::IdentityMismatch,
            ),
            (
                DetailRescanError::MountChanged,
                TuiDetailRescanFailure::MountChanged,
            ),
            (
                DetailRescanError::SymlinkOrReparse,
                TuiDetailRescanFailure::SymlinkOrReparse,
            ),
            (
                DetailRescanError::Cancelled,
                TuiDetailRescanFailure::Cancelled,
            ),
            (
                DetailRescanError::ResourceLimit,
                TuiDetailRescanFailure::ResourceLimit,
            ),
            (
                DetailRescanError::Unavailable,
                TuiDetailRescanFailure::Unavailable,
            ),
        ];
        for (scanner, tui) in cases {
            assert_eq!(map_tui_detail_rescan_error(scanner), tui);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn tui_provider_cancel_hook_notifies_the_active_token() {
        let provider = tui_detail_rescan_provider(&ScanSummary {
            roots: Vec::new(),
            entries: Vec::new(),
            aggregates: Vec::new(),
            boundaries: Vec::new(),
            progress: Vec::new(),
        });
        assert!(provider.live.is_none());
        provider.cancel_detail_rescan();

        let scan_id = ScanId::new("cancel-hook");
        let mut ids = DetailEntryIdAllocator::new(scan_id).unwrap();
        ids.reserve(&ScanEntryId::for_scan_ordinal(&ScanId::new("cancel-hook"), 1).unwrap())
            .unwrap();
        let provider = TuiDetailRescanProvider {
            live: Some(LiveTuiDetailRescanProvider {
                scanner: DetailRescanner::new(
                    HostPlatformScanner::new(),
                    sweepx_platform::ScanResourceLimits::default(),
                ),
                ids: Mutex::new(ids),
                cancel: Mutex::new(CancellationToken::new()),
                progress: Mutex::new(None),
            }),
        };
        provider.cancel_detail_rescan();
        assert!(
            provider
                .live
                .unwrap()
                .cancel
                .into_inner()
                .unwrap()
                .is_cancelled()
        );
    }

    #[test]
    fn cancelled_tui_provider_can_start_a_fresh_followup_query() {
        let temp = tempfile::TempDir::new().unwrap();
        // macOS TMPDIR may contain linked ancestors; native authority rejects those roots.
        #[cfg(unix)]
        let fixture_root = std::fs::canonicalize(temp.path()).unwrap();
        #[cfg(windows)]
        let fixture_root = temp.path().to_path_buf();
        let root_path = fixture_root.join("root");
        std::fs::create_dir(&root_path).unwrap();
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Default,
        ));
        let scan = scan_with_store(
            &context,
            &ScanRequest {
                roots: vec![root_path.clone()],
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
        )
        .unwrap();
        let root = scan.summary.roots[0].clone();
        let root_identity = root.identity.as_ref().unwrap().clone();
        let request = TuiDetailRescanRequest {
            binding: DetailRescanBinding {
                source_scan_id: root.scan_id.clone(),
                source_root_identity: root_identity.clone(),
                source_directory_identity: root_identity,
                base_revision: DecimalU128::new(1),
                revision: DecimalU128::new(2),
            },
            directory_locator: root.executable_native_locator().unwrap().unwrap().clone(),
            reason: DetailRescanReason::Evicted,
            max_rows: 8,
        };
        let provider = tui_detail_rescan_provider(&scan.summary);

        provider.prepare_detail_rescan();
        provider.cancel_detail_rescan();
        assert!(matches!(
            provider.rescan_detail(&request),
            TuiDetailRescanResult::Failed {
                failure: TuiDetailRescanFailure::Cancelled,
                ..
            }
        ));
        provider.prepare_detail_rescan();
        assert!(matches!(
            provider.rescan_detail(&request),
            TuiDetailRescanResult::Refreshed(_)
        ));
    }

    #[test]
    fn live_provider_echoes_binding_and_returns_complete_direct_detail() {
        let temp = tempfile::TempDir::new().unwrap();
        // macOS TMPDIR may contain linked ancestors; native authority rejects those roots.
        #[cfg(unix)]
        let fixture_root = std::fs::canonicalize(temp.path()).unwrap();
        #[cfg(windows)]
        let fixture_root = temp.path().to_path_buf();
        let root_path = fixture_root.join("root");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(root_path.join("child"), b"1234").unwrap();
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Default,
        ));
        let scan = scan_with_store(
            &context,
            &ScanRequest {
                roots: vec![root_path.clone()],
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
        )
        .unwrap();
        let root = scan.summary.roots[0].clone();
        let root_identity = root.identity.as_ref().unwrap().clone();
        let binding = DetailRescanBinding {
            source_scan_id: root.scan_id.clone(),
            source_root_identity: root_identity.clone(),
            source_directory_identity: root_identity,
            base_revision: DecimalU128::new(1),
            revision: DecimalU128::new(2),
        };
        let request = TuiDetailRescanRequest {
            binding: binding.clone(),
            directory_locator: root.executable_native_locator().unwrap().unwrap().clone(),
            reason: DetailRescanReason::Evicted,
            max_rows: 8,
        };
        let provider = tui_detail_rescan_provider(&scan.summary);

        let result = provider.rescan_detail(&request);
        let TuiDetailRescanResult::Refreshed(detail) = result else {
            panic!("live provider unexpectedly failed: {result:?}");
        };
        assert_eq!(detail.binding, binding);
        // An ordinary walk is independent of the scanner/provider path. Pin complete child
        // accounting against it, including any host-created files, rather than relaxing totals.
        let mut expected_names: Vec<_> = std::fs::read_dir(&root_path)
            .unwrap()
            .map(|entry| encoded_name(&entry.unwrap().file_name()))
            .collect();
        let mut observed_names: Vec<_> = detail
            .rows
            .iter()
            .map(|row| row.native_basename.encoded_value())
            .collect();
        expected_names.sort();
        observed_names.sort();
        assert_eq!(observed_names, expected_names);
        assert!(expected_names.contains(&encoded_name(std::ffi::OsStr::new("child"))));
        assert_eq!(detail.aggregate.revision, DecimalU128::new(2));
        assert_eq!(
            detail.aggregate.direct_child_count,
            sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(expected_names.len() as u128),
            }
        );
        assert!(detail.aggregate.coverage.complete);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn progressive_details_observe_files_links_and_nested_bytes_on_macos() {
        use sweepx_model::EvidenceValue;
        let fixture = tempfile::TempDir::new().unwrap();
        let root_path = std::fs::canonicalize(fixture.path()).unwrap().join("root");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(root_path.join("child"), b"1234").unwrap();
        std::fs::create_dir(root_path.join("nested")).unwrap();
        std::fs::write(root_path.join("nested/file"), b"12345").unwrap();
        std::os::unix::fs::symlink("missing-target", root_path.join("link")).unwrap();
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Default,
        ));
        let scan = sweepx_core::scan_for_tui_with_store(
            &context,
            &ScanRequest {
                roots: vec![root_path.clone()],
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
        )
        .unwrap();
        let root = &scan.summary.roots[0];
        let identity = root.validated_identity().unwrap().unwrap();
        let provider = tui_detail_rescan_provider(&scan.summary);
        let mut names: Vec<_> = std::fs::read_dir(&root_path)
            .unwrap()
            .map(|entry| encoded_name(&entry.unwrap().file_name()))
            .collect();
        names.sort();
        // Traverse the controlled fixture with ordinary metadata to check recursive accounting
        // independently. No symlink targets are opened; host-created files remain in the totals.
        fn ordinary_bytes(directory: &std::path::Path) -> u128 {
            std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                    if metadata.is_dir() {
                        ordinary_bytes(&entry.path())
                    } else if metadata.is_file() {
                        metadata.len() as u128
                    } else {
                        0
                    }
                })
                .sum()
        }
        let expected_bytes = ordinary_bytes(&root_path);
        assert!(expected_bytes >= 9);
        for (index, reason) in [
            DetailRescanReason::ProgressiveListing,
            DetailRescanReason::ProgressiveAggregate,
            DetailRescanReason::Evicted,
        ]
        .into_iter()
        .enumerate()
        {
            provider.prepare_detail_rescan();
            let binding = DetailRescanBinding {
                source_scan_id: root.scan_id.clone(),
                source_root_identity: identity.clone(),
                source_directory_identity: identity.clone(),
                base_revision: DecimalU128::new(index as u128 + 1),
                revision: DecimalU128::new(index as u128 + 2),
            };
            let request = TuiDetailRescanRequest {
                binding: binding.clone(),
                directory_locator: root.executable_native_locator().unwrap().unwrap().clone(),
                reason,
                max_rows: 16,
            };
            let result = provider.rescan_detail(&request);
            let TuiDetailRescanResult::Refreshed(detail) = result else {
                panic!("{reason:?}: {result:?}");
            };
            assert_eq!(detail.binding, binding);
            let mut observed: Vec<_> = detail
                .rows
                .iter()
                .map(|row| row.native_basename.encoded_value())
                .collect();
            observed.sort();
            assert_eq!(observed, names);
            assert_eq!(
                detail.aggregate.direct_child_count,
                EvidenceValue::Known {
                    value: DecimalU128::new(names.len() as u128)
                }
            );
            for row in &detail.rows {
                assert!(matches!(
                    row.validated_identity()
                        .unwrap()
                        .unwrap()
                        .volume_or_mount_identity,
                    IdentityEvidence::Known { .. }
                ));
            }
            if reason == DetailRescanReason::ProgressiveListing {
                assert!(!detail.aggregate.coverage.complete);
                assert!(matches!(
                    detail.aggregate.apparent_logical_bytes,
                    EvidenceValue::LowerBound { .. }
                ));
            } else {
                assert!(detail.aggregate.coverage.complete);
                assert_eq!(
                    detail.aggregate.apparent_logical_bytes,
                    EvidenceValue::Known {
                        value: DecimalU128::new(expected_bytes)
                    }
                );
            }
            assert!(matches!(
                detail.aggregate.filesystem_reported_allocated_bytes,
                EvidenceValue::Unknown { .. }
            ));
        }
    }
}
