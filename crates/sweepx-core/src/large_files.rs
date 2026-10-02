//! Independent file ranking shares the ordinary scan, output envelope and native boundaries.

use super::*;
use sweepx_analysis::{
    DuplicateCollector, DuplicateContentSource, DuplicateOptions, DuplicateReport,
    LargeFileCollector,
};
use sweepx_scanner::ClassifiedScanObserver;

/// Runs the ordinary read-only scan and an independent bounded file ranking in the same walk.
/// Every current file reaches the ranking before optional scan-row truncation. Logical size
/// does not classify junk or grant deletion authority. Intended to run on a caller's worker;
/// cancellation uses the provided token and preserves explicitly incomplete results.
pub fn scan_large_files_with_store<S: SnapshotStore>(
    context: &CoreContext,
    request: &ScanRequest,
    store: Option<&S>,
    options: &LargeFileOptions,
    cancel: &CancellationToken,
) -> Result<ScanSuccess, CoreError> {
    // Reject invalid limits before even admitting roots or creating operation state.
    LargeFileCollector::new(options.clone())?;
    scan_with_store_options(
        context,
        request,
        store,
        ScannerOptions::default(),
        None,
        None,
        None,
        Some(FileAnalysisObservation {
            options: FileAnalysisOptions::Large(options),
            cancel,
        }),
    )
    .map(|result| result.scan)
}

pub(super) enum FileAnalysisOptions<'a> {
    Large(&'a LargeFileOptions),
    Duplicates(&'a DuplicateOptions),
}
pub(super) struct FileAnalysisObservation<'a> {
    pub options: FileAnalysisOptions<'a>,
    pub cancel: &'a CancellationToken,
}
enum FileCollector {
    Large(LargeFileCollector),
    Duplicates(DuplicateCollector),
}
pub(super) enum FileAnalysisReport {
    Large(LargeFileReport),
    Duplicates(DuplicateReport),
}
impl FileAnalysisReport {
    pub(super) fn complete(&self) -> bool {
        match self {
            Self::Large(report) => report.complete,
            Self::Duplicates(report) => report.complete,
        }
    }
    pub(super) fn into_data(self) -> (&'static str, Value) {
        match self {
            Self::Large(report) => (
                "largeFiles",
                camelize_json_keys(serde_json::to_value(report).expect("large file report")),
            ),
            Self::Duplicates(report) => (
                "duplicates",
                camelize_json_keys(serde_json::to_value(report).expect("duplicate report")),
            ),
        }
    }
}
pub(super) struct FileAnalysisObserver {
    collector: FileCollector,
    finished: bool,
    incomplete: bool,
    expected_roots: usize,
    completed_roots: usize,
    current_root: Option<PathBuf>,
}

impl FileAnalysisObserver {
    pub(super) fn new(
        options: FileAnalysisOptions<'_>,
        expected_roots: usize,
    ) -> Result<Self, CoreError> {
        Ok(Self {
            collector: match options {
                FileAnalysisOptions::Large(options) => {
                    FileCollector::Large(LargeFileCollector::new(options.clone())?)
                }
                FileAnalysisOptions::Duplicates(options) => {
                    FileCollector::Duplicates(DuplicateCollector::new(options.clone())?)
                }
            },
            finished: false,
            incomplete: false,
            expected_roots,
            completed_roots: 0,
            current_root: None,
        })
    }

    pub(super) fn finish(
        self,
        cancelled: bool,
        source: &mut dyn DuplicateContentSource,
        cancel: &CancellationToken,
    ) -> FileAnalysisReport {
        let complete = self.finished
            && !self.incomplete
            && !cancelled
            && self.completed_roots == self.expected_roots;
        match self.collector {
            FileCollector::Large(collector) => {
                FileAnalysisReport::Large(collector.finish(complete))
            }
            FileCollector::Duplicates(collector) => {
                FileAnalysisReport::Duplicates(collector.analyze(source, complete, cancel))
            }
        }
    }
}

impl ClassifiedScanObserver for FileAnalysisObserver {
    fn on_entry(&mut self, entry: &ScannedEntry) {
        match &mut self.collector {
            FileCollector::Large(collector) => collector.observe(entry),
            FileCollector::Duplicates(collector) => collector.observe(entry),
        }
    }

    fn wants_file_observations(&self) -> bool {
        true
    }

    fn wants_directory_progress(&self) -> bool {
        false
    }

    fn on_progress(&mut self, _root: &Path, event: &ProgressEvent) {
        match event {
            ProgressEvent::RootAccepted { path } => self.current_root = Some(path.clone()),
            ProgressEvent::Finished => self.finished = true,
            ProgressEvent::Error { .. } | ProgressEvent::Cancelled { .. } => self.incomplete = true,
            _ => {}
        }
    }

    fn on_boundary(&mut self, boundary: &BoundaryRecord) {
        // Completeness is for the admitted no-follow scope. Ordinary links are observed and
        // intentionally excluded. A linked/refused root, mount or other omitted scope is a gap.
        // ResourceLimit can describe only optional listing/aggregate retention. Recursive
        // coverage below distinguishes that from refused filesystem observations.
        self.incomplete |= !matches!(
            boundary.kind,
            BoundaryKind::Symlink | BoundaryKind::ResourceLimit
        );
    }

    fn on_directory_coverage(&mut self, path: &Path, coverage: &Coverage) {
        self.incomplete |= !coverage.complete;
        if self.current_root.as_deref() == Some(path) {
            self.completed_roots += 1;
        }
    }
}

pub(super) fn append_human_ranking(
    locale: Locale,
    data: &Value,
    lines: &mut Vec<String>,
    max_rows: usize,
    size_unit: HumanSizeUnit,
) {
    let Some(report) = data.get("largeFiles") else {
        return;
    };
    let complete = report
        .get("complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let headings = match locale {
        Locale::ZhCn => ("路径", "逻辑大小", "分配大小"),
        Locale::EnUs => ("Path", "Logical", "Allocated"),
    };
    lines.push(match locale {
        Locale::ZhCn => format!(
            "大文件榜单（仅报告，按逻辑大小降序）；覆盖{}。",
            if complete { "完整" } else { "不完整" }
        ),
        Locale::EnUs => format!(
            "Large files (report-only, descending logical size); coverage {}.",
            if complete { "complete" } else { "incomplete" }
        ),
    });
    lines.push(format!(
        "{:<56}  {:>14}  {:>14}",
        headings.0, headings.1, headings.2
    ));
    let files = report
        .get("files")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for entry in files.iter().take(max_rows) {
        let path = entry
            .get("displayPath")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let bytes = |key| {
            entry
                .get(key)
                .map(|value| render_human_evidence_value(value, size_unit))
                .unwrap_or_else(|| "unknown".into())
        };
        lines.push(format!(
            "{:<56}  {:>14}  {:>14}",
            truncate_display(&sanitize_terminal_text(path), 56),
            bytes("logicalBytes"),
            bytes("allocatedBytes")
        ));
    }
    lines.push(match locale {
        Locale::ZhCn => format!("已观察 {} 个普通文件，{} 个达到阈值，{} 个逻辑大小不确定；保留 {} 行，显示 {} 行。大文件不是垃圾；硬链接路径可能指向同一内容，分配大小不证明可回收空间。", report["observedFiles"].as_str().unwrap_or("?"), report["qualifyingFiles"].as_str().unwrap_or("?"), report["unknownLogicalFiles"].as_str().unwrap_or("?"), files.len(), files.len().min(max_rows)),
        Locale::EnUs => format!("Observed {} regular files; {} meet the threshold; {} have uncertain logical lengths. Retained {} rows; displayed {}. Large files are not junk; hard-link paths can alias the same content, and allocation does not prove reclaimable space.", report["observedFiles"].as_str().unwrap_or("?"), report["qualifyingFiles"].as_str().unwrap_or("?"), report["unknownLogicalFiles"].as_str().unwrap_or("?"), files.len(), files.len().min(max_rows)),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweepx_platform::ScanResourceLimits;

    fn fixture_root(fixture: &tempfile::TempDir) -> PathBuf {
        #[cfg(unix)]
        {
            fixture.path().canonicalize().unwrap()
        }
        #[cfg(not(unix))]
        {
            fixture.path().to_path_buf()
        }
    }

    fn context() -> CoreContext {
        CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ))
    }

    fn scan(
        root: &Path,
        limits: ScanResourceLimits,
        options: &LargeFileOptions,
        cancel: &CancellationToken,
    ) -> ScanSuccess {
        scan_with_store_options(
            &context(),
            &ScanRequest {
                roots: vec![root.into()],
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
            ScannerOptions {
                resource_limits: limits,
                ..Default::default()
            },
            None,
            None,
            None,
            Some(FileAnalysisObservation {
                options: FileAnalysisOptions::Large(options),
                cancel,
            }),
        )
        .unwrap()
        .scan
    }

    fn report(result: &ScanSuccess) -> LargeFileReport {
        let mut report = result.output.data["largeFiles"].clone();
        report["files"] = decamelize_json_keys(report["files"].take());
        serde_json::from_value(report).unwrap()
    }

    #[test]
    fn large_files_rank_all_metadata_when_ordinary_rows_and_logs_are_truncated() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture_root(&fixture);
        for index in 0..64 {
            fs::write(
                root.join(format!("file-{index}")),
                vec![b'x'; (index * 17) + 1],
            )
            .unwrap();
        }
        let options = LargeFileOptions {
            minimum_logical_bytes: 64.into(),
            max_files: 3,
            ..Default::default()
        };
        let result = scan(
            &root,
            ScanResourceLimits {
                max_retained_entries: 1,
                max_progress_events: 0,
                max_retained_boundaries: 0,
                ..Default::default()
            },
            &options,
            &CancellationToken::new(),
        );
        let report = report(&result);
        assert_eq!(result.output.status, OutputStatus::Partial); // listing truncation stays visible
        assert_eq!(result.summary.entries.len(), 1);
        assert!(result.summary.progress.is_empty() && result.summary.boundaries.is_empty());
        // Ordinary walk/stat is independent of the scanner's retained listing and ordering.
        let mut expected: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.path(), fs::symlink_metadata(entry.path()).unwrap())
            })
            .filter(|(_, metadata)| metadata.is_file())
            .collect();
        assert_eq!(report.observed_files.0, expected.len() as u128);
        expected
            .retain(|(_, metadata)| u128::from(metadata.len()) >= options.minimum_logical_bytes.0);
        assert_eq!(report.qualifying_files.0, expected.len() as u128);
        expected.sort_unstable_by_key(|item| std::cmp::Reverse(item.1.len()));
        expected.truncate(3);
        for (entry, (path, metadata)) in report.files.iter().zip(&expected) {
            assert_eq!(Path::new(&entry.display_path), path);
            assert_eq!(
                entry.logical_bytes,
                EvidenceValue::Known {
                    value: u128::from(metadata.len()).into()
                }
            );
            assert!(entry.identity.is_some() && entry.native_locator.is_some());
            #[cfg(target_os = "linux")]
            assert_eq!(
                entry.allocated_bytes,
                EvidenceValue::Known {
                    value: (u128::from(metadata.blocks()) * 512).into()
                }
            );
            #[cfg(target_os = "macos")]
            assert_eq!(
                entry.allocated_bytes,
                EvidenceValue::Unknown {
                    reason: ReasonCode::UnknownIdentity
                }
            );
        }
        assert_eq!(report.files.len(), 3);
        assert!(report.complete && report.top_k_limited);
    }

    #[test]
    fn large_files_preserve_sparse_allocation_and_hard_link_aliases_without_following_links() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture_root(&fixture);
        let payload = root.join("sparse");
        fs::File::create(&payload)
            .unwrap()
            .set_len(16 * 1024 * 1024)
            .unwrap();
        fs::hard_link(&payload, root.join("alias")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&payload, root.join("link")).unwrap();
        let result = scan(
            &root,
            ScanResourceLimits::default(),
            &LargeFileOptions {
                minimum_logical_bytes: 1.into(),
                ..Default::default()
            },
            &CancellationToken::new(),
        );
        let report = report(&result);
        assert!(report.complete);
        let paths: BTreeSet<_> = report
            .files
            .iter()
            .map(|entry| PathBuf::from(&entry.display_path))
            .collect();
        assert!(paths.contains(&payload) && paths.contains(&root.join("alias")));
        assert!(!paths.contains(&root.join("link")));
        let original = report
            .files
            .iter()
            .find(|entry| Path::new(&entry.display_path) == payload)
            .unwrap();
        let alias = report
            .files
            .iter()
            .find(|entry| Path::new(&entry.display_path) == root.join("alias"))
            .unwrap();
        assert_eq!(
            original.identity.as_ref().unwrap().platform_file_identity,
            alias.identity.as_ref().unwrap().platform_file_identity
        );
        assert_ne!(original.native_locator, alias.native_locator);
        #[cfg(target_os = "linux")]
        assert_eq!(
            original.allocated_bytes,
            EvidenceValue::Known {
                value: (u128::from(fs::symlink_metadata(payload).unwrap().blocks()) * 512).into()
            }
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            original.allocated_bytes,
            EvidenceValue::Unknown {
                reason: ReasonCode::UnknownIdentity
            }
        );
    }

    #[test]
    fn large_files_keep_cancelled_resource_limited_and_retention_limited_scans_incomplete() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture_root(&fixture);
        for index in 0..3 {
            fs::write(root.join(format!("file-{index}")), b"data").unwrap();
        }
        let options = LargeFileOptions {
            minimum_logical_bytes: 0.into(),
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        cancel.cancel();
        let cancelled = scan(&root, ScanResourceLimits::default(), &options, &cancel);
        assert_eq!(cancelled.output.status, OutputStatus::Cancelled);
        assert!(!report(&cancelled).complete);
        let limited = scan(
            &root,
            ScanResourceLimits {
                max_directory_entries: 1,
                max_progress_events: 0,
                max_retained_boundaries: 0,
                ..Default::default()
            },
            &options,
            &CancellationToken::new(),
        );
        assert_eq!(limited.output.status, OutputStatus::Partial);
        assert!(!report(&limited).complete);
        let retained = scan(
            &root,
            ScanResourceLimits::default(),
            &LargeFileOptions {
                max_retained_bytes: 1,
                ..options
            },
            &CancellationToken::new(),
        );
        assert_eq!(retained.output.status, OutputStatus::Partial);
        let report = report(&retained);
        assert!(report.files.is_empty() && !report.complete);
        assert_eq!(
            report.incomplete_reasons,
            vec![sweepx_analysis::LargeFileIncompleteReason::RetentionLimit]
        );
    }

    #[test]
    fn large_files_share_one_global_top_k_across_current_roots() {
        let fixture = tempfile::tempdir().unwrap();
        let base = fixture_root(&fixture);
        let roots: Vec<_> = ["a", "b"].map(|name| base.join(name)).into();
        for (index, root) in roots.iter().enumerate() {
            fs::create_dir(root).unwrap();
            fs::write(root.join("payload"), vec![b'x'; 100 + index]).unwrap();
        }
        let result = scan_large_files_with_store(
            &context(),
            &ScanRequest {
                roots: roots.clone(),
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
            &LargeFileOptions {
                minimum_logical_bytes: 0.into(),
                max_files: 1,
                ..Default::default()
            },
            &CancellationToken::new(),
        )
        .unwrap();
        let report = report(&result);
        let mut oracle: Vec<_> = roots
            .iter()
            .flat_map(|root| fs::read_dir(root).unwrap())
            .map(|entry| entry.unwrap().path())
            .filter(|path| fs::symlink_metadata(path).unwrap().is_file())
            .collect();
        assert_eq!(report.observed_files.0, oracle.len() as u128);
        oracle.sort_unstable_by_key(|path| {
            std::cmp::Reverse(fs::symlink_metadata(path).unwrap().len())
        });
        assert_eq!(report.files.len(), 1);
        assert_eq!(Path::new(&report.files[0].display_path), &oracle[0]);
        assert!(report.complete && report.top_k_limited);
    }

    #[test]
    fn large_files_reject_invalid_limits_before_root_observation() {
        let result = scan_large_files_with_store(
            &context(),
            &ScanRequest {
                roots: vec![PathBuf::from("not-absolute")],
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
            &LargeFileOptions {
                max_files: 0,
                ..Default::default()
            },
            &CancellationToken::new(),
        );
        assert!(matches!(result, Err(CoreError::InvalidLargeFileOptions(_))));
    }
}
