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
            sink: None,
        }),
        ScanProjection::Materialized,
    )
    .map(|result| result.scan)
}

/// Independent analysis requested for the same metadata traversal.
#[derive(Clone, Copy)]
pub enum FileAnalysisOptions<'a> {
    /// Logical-size ranking, without content IO.
    Large(&'a LargeFileOptions),
    /// Explicit bounded content reads, without keeper or deletion choices.
    Duplicates(&'a DuplicateOptions),
}
/// Synchronous worker callbacks. Consumers bound retained copies/queues and never render or
/// perform native mutation from these callbacks. Only the enclosing scan return is terminal.
pub trait FileAnalysisSink {
    /// Coalescible provisional ranking while metadata traversal remains open.
    fn on_large_files(&mut self, _report: &LargeFileReport) {}
    /// Final ranking, possibly incomplete. Deliver reliably before the enclosing return;
    /// even a complete ranking cannot hide a later state-persistence failure.
    fn on_large_files_final(&mut self, report: &LargeFileReport) {
        self.on_large_files(report);
    }
    /// Full-hash group with live final stamps; this is not whole-scope completion.
    fn on_duplicate_group(&mut self, _group: &sweepx_analysis::DuplicateGroup) {}
    /// Coalescible current metadata/IO progress; path is presentation only.
    fn on_progress(&mut self, _phase: &'static str, _count: u128, _path: &str) {}
}

/// Terminal metadata for an analysis whose native rows have already reached its sink.
///
/// This is not a scan JSON export or deletion permit. The enclosing status includes traversal
/// gaps and cancellation; a callback can precede a later persistence error. All required state
/// writes finish before this value is returned, and errors still return `CoreError` instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAnalysisCompletion {
    /// Final enclosing scan/analysis status, independent of provisional row completeness.
    pub status: OutputStatus,
    /// Operation identity retained for status/evidence correlation without a full envelope.
    pub operation_id: OperationId,
    /// Native scan identity, absent only when no supported traversal could run.
    pub scan_id: Option<ScanId>,
    /// Stable snake_case names from the finite analysis reason enums (at most nine).
    /// These describe the collector; an empty list does not override a non-OK enclosing status.
    pub incomplete_reasons: Vec<String>,
}

/// Runs the same metadata/content stages and reliable callbacks without projecting all scan
/// rows, analysis files or unused post-scan events into JSON. Use this worker seam when the sink
/// already owns bounded live results. Legacy observer/export entry points remain unchanged.
///
/// Scanner/collector retention and optional preview persistence keep their existing bounds.
/// Required Linux journal events are still built and persisted when `state_dir` is supplied.
/// Cancellation and state errors cannot become successful completion or mutation authority.
pub fn scan_file_analysis_completion_with_observer<S: SnapshotStore>(
    context: &CoreContext,
    request: &ScanRequest,
    store: Option<&S>,
    options: FileAnalysisOptions<'_>,
    cancel: &CancellationToken,
    sink: &mut dyn FileAnalysisSink,
) -> Result<FileAnalysisCompletion, CoreError> {
    validate_options(options)?;
    scan_with_store_options(
        context,
        request,
        store,
        ScannerOptions::default(),
        None,
        None,
        None,
        Some(FileAnalysisObservation {
            options,
            cancel,
            sink: Some(sink),
        }),
        ScanProjection::AnalysisObserver,
    )
    .map(|result| FileAnalysisCompletion {
        status: result.scan.output.status,
        operation_id: result.scan.output.operation_id,
        scan_id: result.scan.snapshot.scan_id.map(ScanId::new),
        incomplete_reasons: result.analysis_incomplete_reasons.unwrap_or_default(),
    })
}

fn validate_options(options: FileAnalysisOptions<'_>) -> Result<(), CoreError> {
    match options {
        FileAnalysisOptions::Large(options) => {
            LargeFileCollector::new(options.clone())?;
        }
        FileAnalysisOptions::Duplicates(options) => {
            DuplicateCollector::new(options.clone())?;
        }
    }
    Ok(())
}

/// Runs the existing analysis with worker-local callbacks. Cancellation, state/output and
/// resource semantics are identical to the ordinary large-file/duplicate entry points.
pub fn scan_file_analysis_with_observer<S: SnapshotStore>(
    context: &CoreContext,
    request: &ScanRequest,
    store: Option<&S>,
    options: FileAnalysisOptions<'_>,
    cancel: &CancellationToken,
    sink: &mut dyn FileAnalysisSink,
) -> Result<ScanSuccess, CoreError> {
    validate_options(options)?;
    scan_with_store_options(
        context,
        request,
        store,
        ScannerOptions::default(),
        None,
        None,
        None,
        Some(FileAnalysisObservation {
            options,
            cancel,
            sink: Some(sink),
        }),
        ScanProjection::Materialized,
    )
    .map(|result| result.scan)
}
pub(super) struct FileAnalysisObservation<'a> {
    pub options: FileAnalysisOptions<'a>,
    pub cancel: &'a CancellationToken,
    pub sink: Option<&'a mut dyn FileAnalysisSink>,
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

    pub(super) fn into_reason_names(self) -> Vec<String> {
        // Only the finite reason enums are serialized, never file/native-locator payloads.
        // Moving these vectors releases the final report rows before state persistence/return.
        let reasons = match self {
            Self::Large(report) => serde_json::to_value(report.incomplete_reasons),
            Self::Duplicates(report) => serde_json::to_value(report.incomplete_reasons),
        }
        .expect("analysis reason enums are serializable");
        serde_json::from_value(reasons).expect("analysis reason enums serialize as string names")
    }
}
pub(super) struct FileAnalysisObserver<'a> {
    collector: FileCollector,
    finished: bool,
    incomplete: bool,
    expected_roots: usize,
    completed_roots: usize,
    current_root: Option<PathBuf>,
    sink: Option<&'a mut dyn FileAnalysisSink>,
    last_preview: Option<Instant>,
    observed_files: u128,
}

impl<'a> FileAnalysisObserver<'a> {
    pub(super) fn new(
        options: FileAnalysisOptions<'_>,
        expected_roots: usize,
        sink: Option<&'a mut dyn FileAnalysisSink>,
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
            sink,
            last_preview: None,
            observed_files: 0,
        })
    }

    pub(super) fn finish(
        mut self,
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
                let report = collector.finish(complete);
                if let Some(sink) = self.sink.as_deref_mut() {
                    sink.on_large_files_final(&report);
                }
                FileAnalysisReport::Large(report)
            }
            FileCollector::Duplicates(collector) => {
                if let Some(sink) = self.sink {
                    struct Bridge<'a>(&'a mut dyn FileAnalysisSink);
                    impl sweepx_analysis::DuplicateAnalysisObserver for Bridge<'_> {
                        fn on_read(&mut self, entry: &ScannedEntry, _charged: u64, delivered: u64) {
                            self.0
                                .on_progress("content", delivered.into(), &entry.display_path);
                        }
                        fn on_group(&mut self, group: &sweepx_analysis::DuplicateGroup) {
                            self.0.on_duplicate_group(group);
                        }
                    }
                    FileAnalysisReport::Duplicates(collector.analyze_with_observer(
                        source,
                        complete,
                        cancel,
                        &mut Bridge(sink),
                    ))
                } else {
                    FileAnalysisReport::Duplicates(collector.analyze(source, complete, cancel))
                }
            }
        }
    }
}

impl ClassifiedScanObserver for FileAnalysisObserver<'_> {
    fn on_entry(&mut self, entry: &ScannedEntry) {
        if entry.object_type == ObjectType::File {
            self.observed_files = self.observed_files.saturating_add(1);
        }
        match &mut self.collector {
            FileCollector::Large(collector) => collector.observe(entry),
            FileCollector::Duplicates(collector) => collector.observe(entry),
        }
        if let Some(sink) = self.sink.as_deref_mut() {
            match &self.collector {
                FileCollector::Large(collector) => {
                    if self
                        .last_preview
                        .is_none_or(|last| last.elapsed() >= Duration::from_millis(100))
                    {
                        let preview = collector.preview();
                        if !preview.files.is_empty() {
                            self.last_preview = Some(Instant::now());
                            sink.on_large_files(&preview);
                        }
                    }
                }
                FileCollector::Duplicates(_) => {}
            }
            sink.on_progress("traversal", self.observed_files, &entry.display_path);
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

    #[test]
    fn a_final_ranking_callback_does_not_hide_a_later_state_failure() {
        struct RejectState;
        impl SnapshotStore for RejectState {
            fn save(&self, _snapshot: &OperationSnapshot) -> Result<(), StateError> {
                Err(StateError::Io(std::io::Error::other(
                    "controlled state failure",
                )))
            }
            fn load(&self, _operation_id: &str) -> Result<Option<OperationSnapshot>, StateError> {
                Ok(None)
            }
        }
        #[derive(Default)]
        struct Sink {
            final_report: Option<LargeFileReport>,
            provisional: bool,
        }
        impl FileAnalysisSink for Sink {
            fn on_large_files(&mut self, report: &LargeFileReport) {
                if report.complete {
                    self.final_report = Some(report.clone());
                } else {
                    self.provisional |= !report.files.is_empty();
                }
            }
        }
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture_root(&fixture);
        fs::write(root.join("one"), b"payload").unwrap();
        for completion_only in [false, true] {
            let mut sink = Sink::default();
            let request = ScanRequest {
                roots: vec![root.clone()],
                state_dir: None,
            };
            let options = LargeFileOptions {
                minimum_logical_bytes: 0.into(),
                ..Default::default()
            };
            let cancel = CancellationToken::new();
            let result = if completion_only {
                scan_file_analysis_completion_with_observer(
                    &context(),
                    &request,
                    Some(&RejectState),
                    FileAnalysisOptions::Large(&options),
                    &cancel,
                    &mut sink,
                )
                .map(|result| result.status)
            } else {
                scan_file_analysis_with_observer(
                    &context(),
                    &request,
                    Some(&RejectState),
                    FileAnalysisOptions::Large(&options),
                    &cancel,
                    &mut sink,
                )
                .map(|result| result.output.status)
            };
            assert!(matches!(result, Err(CoreError::State(StateError::Io(_)))));
            assert!(sink.provisional);
            let report = sink.final_report.unwrap();
            assert_eq!(report.files.len(), 1);
            assert_eq!(
                report.files[0].logical_bytes,
                sweepx_platform::known_u128(u128::from(
                    fs::metadata(root.join("one")).unwrap().len()
                ))
            );
        }
    }

    #[test]
    fn completion_observer_preserves_ranking_and_snapshot_without_json_row_copies() {
        #[derive(Default)]
        struct Sink(Option<LargeFileReport>);
        impl FileAnalysisSink for Sink {
            fn on_large_files_final(&mut self, report: &LargeFileReport) {
                self.0 = Some(report.clone());
            }
        }
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture_root(&fixture);
        for index in 1..=40 {
            fs::write(root.join(format!("file-{index}")), vec![b'x'; index]).unwrap();
        }
        let request = ScanRequest {
            roots: vec![root.clone()],
            state_dir: None,
        };
        let options = LargeFileOptions {
            minimum_logical_bytes: 0.into(),
            max_files: 3,
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        let mut legacy_sink = Sink::default();
        let legacy = scan_file_analysis_with_observer(
            &context(),
            &request,
            Option::<&MemorySnapshotStore>::None,
            FileAnalysisOptions::Large(&options),
            &cancel,
            &mut legacy_sink,
        )
        .unwrap();
        let store = MemorySnapshotStore::default();
        let mut sink = Sink::default();
        let work = scan_with_store_options(
            &context(),
            &request,
            Some(&store),
            ScannerOptions::default(),
            None,
            None,
            None,
            Some(FileAnalysisObservation {
                options: FileAnalysisOptions::Large(&options),
                cancel: &cancel,
                sink: Some(&mut sink),
            }),
            ScanProjection::AnalysisObserver,
        )
        .unwrap();
        // Check the internal representation, not just the small value returned after dropping
        // a materialized export. Legacy output is still available to export consumers.
        assert_eq!(work.scan.output.data, json!({}));
        assert!(work.scan.events.is_empty());
        assert!(!work.scan.summary.entries.is_empty());
        assert!(!legacy.output.data["entries"].as_array().unwrap().is_empty());
        assert!(!legacy.events.is_empty());
        assert_eq!(work.analysis_incomplete_reasons, Some(Vec::new()));
        assert_eq!(work.scan.output.status, OutputStatus::Ok);
        assert_eq!(work.scan.snapshot.status, legacy.snapshot.status);
        assert_eq!(work.scan.snapshot.state, legacy.snapshot.state);
        assert_eq!(work.scan.snapshot.entry_count, legacy.snapshot.entry_count);
        assert_eq!(work.scan.snapshot.error_count, legacy.snapshot.error_count);
        assert_eq!(
            work.scan.snapshot.boundary_count,
            legacy.snapshot.boundary_count
        );
        assert_eq!(
            store.load(&work.scan.snapshot.operation_id).unwrap(),
            Some(work.scan.snapshot)
        );

        let report = sink.0.unwrap();
        let legacy_report = legacy_sink.0.unwrap();
        assert!(report.complete && legacy_report.complete);
        // An ordinary walk/stat is independent of both native scanner projections.
        let mut oracle: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), fs::symlink_metadata(path).unwrap())
            })
            .filter(|(_, metadata)| metadata.is_file())
            .collect();
        assert_eq!(report.observed_files.0, oracle.len() as u128);
        oracle.sort_unstable_by_key(|(_, metadata)| std::cmp::Reverse(metadata.len()));
        oracle.truncate(3);
        assert_eq!(report.files.len(), oracle.len());
        for ((entry, legacy_entry), (path, metadata)) in
            report.files.iter().zip(&legacy_report.files).zip(oracle)
        {
            assert_eq!(Path::new(&entry.display_path), path);
            assert_eq!(
                entry.logical_bytes,
                sweepx_platform::known_u128(u128::from(metadata.len()))
            );
            assert_eq!(entry.display_path, legacy_entry.display_path);
            assert_eq!(entry.logical_bytes, legacy_entry.logical_bytes);
            assert_eq!(entry.allocated_bytes, legacy_entry.allocated_bytes);
            assert_eq!(
                entry.identity.as_ref().unwrap().platform_file_identity,
                legacy_entry
                    .identity
                    .as_ref()
                    .unwrap()
                    .platform_file_identity
            );
            assert!(entry.native_locator.is_some());
        }
    }

    #[test]
    fn completion_observer_keeps_final_callback_cancellation_and_collector_gaps_explicit() {
        struct Sink(CancellationToken);
        impl FileAnalysisSink for Sink {
            fn on_large_files_final(&mut self, report: &LargeFileReport) {
                assert!(report.complete);
                self.0.cancel();
            }
        }
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture_root(&fixture);
        fs::write(root.join("one"), b"payload").unwrap();
        let request = ScanRequest {
            roots: vec![root],
            state_dir: None,
        };
        let options = LargeFileOptions {
            minimum_logical_bytes: 0.into(),
            ..Default::default()
        };
        let cancel = CancellationToken::new();
        let store = MemorySnapshotStore::default();
        let completion = scan_file_analysis_completion_with_observer(
            &context(),
            &request,
            Some(&store),
            FileAnalysisOptions::Large(&options),
            &cancel,
            &mut Sink(cancel.clone()),
        )
        .unwrap();
        assert_eq!(completion.status, OutputStatus::Cancelled);
        // The final callback had complete collector coverage. That does not overrule enclosing
        // cancellation or allow the TUI to interpret an empty reason list as successful.
        assert!(completion.incomplete_reasons.is_empty());
        let snapshot = store.load(&completion.operation_id).unwrap().unwrap();
        assert_eq!(snapshot.status, completion.status);
        assert_eq!(snapshot.scan_id.as_deref(), completion.scan_id.as_deref());

        struct Quiet;
        impl FileAnalysisSink for Quiet {}
        let limited = scan_file_analysis_completion_with_observer(
            &context(),
            &request,
            Option::<&MemorySnapshotStore>::None,
            FileAnalysisOptions::Large(&LargeFileOptions {
                max_retained_bytes: 1,
                ..options
            }),
            &CancellationToken::new(),
            &mut Quiet,
        )
        .unwrap();
        assert_eq!(limited.status, OutputStatus::Partial);
        assert_eq!(limited.incomplete_reasons, ["retention_limit"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completion_observer_still_persists_the_required_linux_journal() {
        struct Sink;
        impl FileAnalysisSink for Sink {}
        let fixture = tempfile::tempdir_in("/dev/shm").unwrap();
        let root = fixture_root(&fixture);
        fs::write(root.join("one"), b"payload").unwrap();
        let state_fixture = tempfile::tempdir().unwrap();
        let state_dir = state_fixture.path().join("state");
        let store = DurableSnapshotStore::new(&state_dir).unwrap();
        let context = context();
        let completion = scan_file_analysis_completion_with_observer(
            &context,
            &ScanRequest {
                roots: vec![root],
                state_dir: Some(state_dir.clone()),
            },
            Some(&store),
            FileAnalysisOptions::Large(&LargeFileOptions {
                minimum_logical_bytes: 0.into(),
                ..Default::default()
            }),
            &CancellationToken::new(),
            &mut Sink,
        )
        .unwrap();
        assert_eq!(completion.status, OutputStatus::Ok);
        let operation_id = ValidatedOperationId::parse(&completion.operation_id).unwrap();
        let journal = EventJournal::open(store.journal_dir(&operation_id)).unwrap();
        let stored = journal.read_final_snapshot().unwrap().unwrap();
        let snapshot: OperationSnapshot =
            serde_json::from_slice(stored.canonical_snapshot()).unwrap();
        assert_eq!(snapshot.status, completion.status);
        assert_eq!(snapshot.scan_id.as_deref(), completion.scan_id.as_deref());
        assert_eq!(
            snapshot.terminal_event_type.as_deref(),
            Some("operation.terminal")
        );
        assert!(!state_dir.join("operations").exists());
        drop(journal);
        let status = status_with_store(
            &context,
            &StatusRequest {
                operation_id: completion.operation_id.to_string(),
                state_dir: Some(state_dir),
            },
            Some(&store),
        )
        .unwrap();
        assert_eq!(status.snapshot, Some(snapshot));
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
                sink: None,
            }),
            ScanProjection::Materialized,
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
        struct Sink;
        impl FileAnalysisSink for Sink {}
        let result = scan_file_analysis_completion_with_observer(
            &context(),
            &ScanRequest {
                roots: vec![PathBuf::from("not-absolute")],
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
            FileAnalysisOptions::Large(&LargeFileOptions {
                max_files: 0,
                ..Default::default()
            }),
            &CancellationToken::new(),
            &mut Sink,
        );
        assert!(matches!(result, Err(CoreError::InvalidLargeFileOptions(_))));
    }
}
