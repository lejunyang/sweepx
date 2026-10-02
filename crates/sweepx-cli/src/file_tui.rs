//! File analyses reuse the shared bounded list. Native work stays on one cancellable worker;
//! source rows and content stamps stay private here, never reconstructed from presentation.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sweepx_core::{
    CancellationToken, CoreContext, DuplicateGroup, DuplicateOptions, DurableSnapshotStore,
    FileAnalysisOptions, FileAnalysisSink, LargeFileOptions, LargeFileReport, ScanRequest,
};
use sweepx_i18n::Locale;
use sweepx_model::{ByteValue, EvidenceValue, HumanSizeUnit, ScanSort, ScannedEntry};
use sweepx_platform::RegularFileObservation;
use sweepx_protocol::OutputStatus;
use sweepx_tui::junk::{
    JunkEvent, JunkOutcome, JunkProvider, JunkRow, ResultPresentation, run_junk_browser,
};

const MAX_ROWS: usize = 16_384;
const MAX_BYTES: usize = 64 * 1024 * 1024;
static ANALYSIS_ACTIVE: AtomicBool = AtomicBool::new(false);
struct AnalysisPermit;
impl Drop for AnalysisPermit {
    fn drop(&mut self) {
        ANALYSIS_ACTIVE.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
/// Shared analysis limits owned by one background view revision.
pub(crate) enum Options {
    /// Metadata-only logical-size ranking.
    Large(LargeFileOptions),
    /// Explicit bounded content analysis.
    Duplicates(DuplicateOptions),
}
impl Options {
    fn borrowed(&self) -> FileAnalysisOptions<'_> {
        match self {
            Self::Large(options) => FileAnalysisOptions::Large(options),
            Self::Duplicates(options) => FileAnalysisOptions::Duplicates(options),
        }
    }
    fn presentation(&self) -> ResultPresentation {
        match self {
            Self::Large(_) => ResultPresentation::LargeFiles,
            Self::Duplicates(_) => ResultPresentation::Duplicates,
        }
    }
}

#[derive(Clone)]
struct Row {
    key: String,
    rule: String,
    entry: Arc<ScannedEntry>,
    stamp: Option<RegularFileObservation>,
    group: Option<String>,
    keeper: bool,
    complete: bool,
    locale: Locale,
}
impl Row {
    fn new(
        entry: &ScannedEntry,
        group: Option<(&DuplicateGroup, usize)>,
        complete: bool,
        locale: Locale,
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"sweepx.file-view/v1\0");
        // Stable native path and full object identities, without single-scan entry IDs. Unknown
        // locators can have an invocation-local display key, but never pass complete()/mutation.
        if let Ok(Some(locator)) = entry.validated_native_locator() {
            hash.update(serde_json::to_vec(&locator.scan_root_absolute_path).expect("native path"));
            for component in locator
                .parent_reopen_recipe
                .iter()
                .skip(1)
                .chain([&locator.entry])
            {
                hash.update(serde_json::to_vec(&component.native_basename).expect("native name"));
            }
            hash.update(
                serde_json::to_vec(&locator.entry.platform_file_identity).expect("identity"),
            );
            hash.update(
                serde_json::to_vec(&locator.entry.filesystem_object_domain_identity)
                    .expect("filesystem"),
            );
            // File mount evidence is established live on macOS, so bind the captured root
            // mount instead of changing keys when the content stage adds file mount facts.
            hash.update(
                serde_json::to_vec(&locator.scan_root.volume_or_mount_identity).expect("mount"),
            );
        } else {
            hash.update(entry.scan_id.as_bytes());
            hash.update(entry.display_path.as_bytes());
        }
        let group_key =
            group.map(|(group, _)| format!("{}:{}", group.logical_bytes.0, group.sha256));
        if let Some(key) = &group_key {
            hash.update(key.as_bytes());
        }
        Self {
            key: format!("{:x}", hash.finalize()),
            rule: group.map_or_else(
                || "large_file".into(),
                |(group, _)| format!("SHA-256 {}", group.sha256),
            ),
            entry: Arc::new(entry.clone()),
            stamp: group.and_then(|(group, index)| group.live_observations.get(index).cloned()),
            group: group_key,
            keeper: false,
            complete,
            locale,
        }
    }
}
impl JunkRow for Row {
    fn key(&self) -> &str {
        &self.key
    }
    fn path(&self) -> &str {
        &self.entry.display_path
    }
    fn rule(&self) -> &str {
        &self.rule
    }
    fn evidence(&self) -> &str {
        match (self.locale, self.group.is_some()) {
            (Locale::ZhCn, true) => {
                "完整 SHA-256 相同且原生对象不同；按 p 选择保留者。内容相同不代表可丢弃。"
            }
            (Locale::ZhCn, false) => "按逻辑大小排名；大小不能证明是垃圾或实际可释放空间。",
            (Locale::EnUs, true) => {
                "Full SHA-256; different native objects; choose a keeper with p. Content equality does not establish disposability."
            }
            (Locale::EnUs, false) => {
                "Logical-size ranking; size does not establish disposability or reclaimable space."
            }
        }
    }
    fn context(&self) -> String {
        let labels = match self.locale {
            Locale::ZhCn => ["分配大小", "内容组", "保留者", "覆盖完整"],
            Locale::EnUs => ["allocated", "group", "keeper", "coverage"],
        };
        let text = |zh, en| if self.locale == Locale::ZhCn { zh } else { en };
        let allocated = match &self.entry.allocated_bytes {
            EvidenceValue::Known { value } => HumanSizeUnit::Auto.format(value.0),
            EvidenceValue::LowerBound { value, .. } => {
                format!("≥ {}", HumanSizeUnit::Auto.format(value.0))
            }
            EvidenceValue::Unknown { .. } => text("未知", "unknown").into(),
            EvidenceValue::NotChecked { .. } => text("未核验", "not checked").into(),
            EvidenceValue::Unsupported { .. } => text("不支持", "unsupported").into(),
        };
        format!(
            "{}={} · {}={} · {}={} · {}={}",
            labels[0],
            allocated,
            labels[1],
            self.group
                .as_deref()
                .unwrap_or(text("不适用", "not applicable")),
            labels[2],
            if self.keeper {
                text("是", "yes")
            } else {
                text("否", "no")
            },
            labels[3],
            if self.complete {
                text("是", "yes")
            } else {
                text("否", "no")
            }
        )
    }
    fn logical_bytes(&self) -> &ByteValue {
        &self.entry.logical_bytes
    }
    fn complete(&self) -> bool {
        self.complete
            && (self.group.is_none() || self.stamp.is_some())
            && self.entry.coverage.complete
            && !self.entry.coverage.details_lost
            && self
                .entry
                .validated_native_locator()
                .ok()
                .flatten()
                .is_some()
    }
    fn report_allows_trash(&self) -> bool {
        !self.keeper
    }
    fn retained_bytes(&self) -> usize {
        self.entry
            .estimated_retained_bytes()
            .saturating_mul(2)
            .saturating_add(1024)
    }
}

enum Packet {
    Large(Vec<Arc<Row>>),
    Group(Vec<Arc<Row>>),
    End(JunkOutcome, String),
}
struct Progress {
    phase: &'static str,
    count: u64,
    path: String,
}
struct Sink {
    sender: SyncSender<Packet>,
    closed: Arc<AtomicBool>,
    progress: Arc<Mutex<Option<Progress>>>,
    preview: Arc<Mutex<Option<Vec<Arc<Row>>>>>,
    last_progress: Option<Instant>,
    cancel: CancellationToken,
    rejected: bool,
    locale: Locale,
}
impl Sink {
    fn send(&self, mut packet: Packet) {
        // One reliable slot plus the producer's one bounded payload. Closing releases blocked
        // publication without joining an uninterruptible filesystem call on the UI thread.
        while !self.closed.load(Ordering::Acquire) {
            match self.sender.try_send(packet) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => return,
                Err(TrySendError::Full(value)) => packet = value,
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn rows(
        &mut self,
        entries: &[ScannedEntry],
        group: Option<&DuplicateGroup>,
        complete: bool,
    ) -> Vec<Arc<Row>> {
        let mut rows = Vec::new();
        let mut cost = 0usize;
        for (index, entry) in entries.iter().enumerate() {
            let row = Row::new(
                entry,
                group.map(|group| (group, index)),
                complete,
                self.locale,
            );
            cost = cost.saturating_add(row.retained_bytes());
            if rows.len() >= MAX_ROWS || cost > MAX_BYTES {
                self.rejected = true;
                self.cancel.cancel();
                break;
            }
            rows.push(Arc::new(row));
        }
        rows
    }
}
impl FileAnalysisSink for Sink {
    fn on_large_files(&mut self, report: &LargeFileReport) {
        let rows = self.rows(&report.files, None, report.complete);
        *self.preview.lock().unwrap() = Some(rows);
    }
    fn on_large_files_final(&mut self, report: &LargeFileReport) {
        let rows = self.rows(&report.files, None, report.complete);
        self.send(Packet::Large(rows));
    }
    fn on_duplicate_group(&mut self, group: &DuplicateGroup) {
        let rows = self.rows(&group.files, Some(group), true);
        self.send(Packet::Group(rows));
    }
    fn on_progress(&mut self, phase: &'static str, count: u128, path: &str) {
        if self
            .last_progress
            .is_some_and(|last| last.elapsed() < Duration::from_millis(50))
        {
            return;
        }
        self.last_progress = Some(Instant::now());
        let mut end = path.len().min(2048);
        while !path.is_char_boundary(end) {
            end -= 1;
        }
        let path = path[..end].to_string();
        *self.progress.lock().unwrap() = Some(Progress {
            phase,
            count: count.min(u64::MAX as u128) as u64,
            path,
        });
    }
}

struct Provider {
    context: CoreContext,
    request: ScanRequest,
    store: Option<DurableSnapshotStore>,
    options: Options,
    rows: BTreeMap<String, Arc<Row>>,
    live_keys: BTreeSet<String>,
    keepers: BTreeMap<String, String>,
    revision: u64,
    busy: bool,
    complete: bool,
    retained: usize,
    rejected: bool,
    receiver: Option<Receiver<Packet>>,
    progress: Arc<Mutex<Option<Progress>>>,
    preview: Arc<Mutex<Option<Vec<Arc<Row>>>>>,
    cancel: CancellationToken,
    closed: Arc<AtomicBool>,
    pending: VecDeque<JunkEvent>,
    trash: Option<Receiver<(String, Result<(), String>)>>,
}
impl Provider {
    fn new(
        context: CoreContext,
        request: ScanRequest,
        store: Option<DurableSnapshotStore>,
        options: Options,
    ) -> Result<Self, String> {
        let mut provider = Self {
            context,
            request,
            store,
            options,
            rows: BTreeMap::new(),
            live_keys: BTreeSet::new(),
            keepers: BTreeMap::new(),
            revision: 0,
            busy: false,
            complete: false,
            retained: 0,
            rejected: false,
            receiver: None,
            progress: Arc::new(Mutex::new(None)),
            preview: Arc::new(Mutex::new(None)),
            cancel: CancellationToken::new(),
            closed: Arc::new(AtomicBool::new(false)),
            pending: VecDeque::new(),
            trash: None,
        };
        provider.start()?;
        Ok(provider)
    }
    fn start(&mut self) -> Result<(), String> {
        if self.busy
            || self.trash.is_some()
            || !self.pending.is_empty()
            || self.closed.load(Ordering::Acquire)
        {
            return Err("worker busy or closed".into());
        }
        let revision = self.revision.checked_add(1).ok_or("revision exhausted")?;
        ANALYSIS_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "a file analysis worker is still running".to_string())?;
        let permit = AnalysisPermit;
        let context = self.context.clone();
        let request = ScanRequest {
            roots: self.request.roots.clone(),
            state_dir: self.request.state_dir.clone(),
        };
        let store = self.store.clone();
        let options = self.options.clone();
        let cancel = CancellationToken::new();
        let closed = self.closed.clone();
        let progress = self.progress.clone();
        let preview = self.preview.clone();
        let (sender, receiver) = sync_channel(1);
        let worker_cancel = cancel.clone();
        std::thread::Builder::new()
            .name("sweepx-file-analysis".into())
            .spawn(move || {
                let mut sink = Sink {
                    sender,
                    closed,
                    progress,
                    preview,
                    last_progress: None,
                    cancel: worker_cancel.clone(),
                    rejected: false,
                    locale: context.locale(),
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    sweepx_core::scan_file_analysis_with_observer(
                        &context,
                        &request,
                        store.as_ref(),
                        options.borrowed(),
                        &worker_cancel,
                        &mut sink,
                    )
                }));
                let (outcome, message) = match result {
                    Ok(Ok(scan)) => {
                        let outcome = match scan.output.status {
                            OutputStatus::Ok if !sink.rejected => JunkOutcome::Complete,
                            OutputStatus::Cancelled => JunkOutcome::Cancelled,
                            _ => JunkOutcome::Partial,
                        };
                        let reasons = scan
                            .output
                            .data
                            .get("duplicates")
                            .or_else(|| scan.output.data.get("largeFiles"))
                            .and_then(|value| value.get("incompleteReasons"))
                            .map(|value| value.to_string())
                            .unwrap_or_default();
                        (
                            outcome,
                            if outcome == JunkOutcome::Complete {
                                String::new()
                            } else {
                                format!("analysis incomplete: {reasons}")
                            },
                        )
                    }
                    Ok(Err(error)) => (JunkOutcome::Failed, error.to_string()),
                    Err(_) => (
                        JunkOutcome::Failed,
                        "analysis worker panicked; results incomplete".into(),
                    ),
                };
                // No native work remains. Release before publishing completion so an immediate
                // refresh cannot race the worker's trailing destructor. Blocked native work keeps
                // this permit even after close; only its eventual return reaches this point.
                drop(permit);
                sink.send(Packet::End(outcome, message));
            })
            .map_err(|error| error.to_string())?;
        self.revision = revision;
        self.receiver = Some(receiver);
        self.cancel = cancel;
        self.busy = true;
        self.complete = false;
        self.rejected = false;
        self.live_keys.clear();
        self.keepers.clear();
        *self.progress.lock().unwrap() = None;
        *self.preview.lock().unwrap() = None;
        self.pending.push_back(JunkEvent::Started {
            revision,
            keys: None,
        });
        Ok(())
    }
    fn admit(&mut self, row: Arc<Row>) {
        let old = self
            .rows
            .get(&row.key)
            .map_or(0, |row| row.retained_bytes());
        let cost = self
            .retained
            .saturating_sub(old)
            .saturating_add(row.retained_bytes());
        if cost > MAX_BYTES || (!self.rows.contains_key(&row.key) && self.rows.len() >= MAX_ROWS) {
            if !self.rejected {
                self.pending.push_back(JunkEvent::Error {
                    revision: self.revision,
                    message: "file view retention limit; results incomplete".into(),
                });
            }
            self.rejected = true;
            self.cancel.cancel();
            return;
        }
        self.retained = cost;
        self.live_keys.insert(row.key.clone());
        self.rows.insert(row.key.clone(), row.clone());
        self.pending.push_back(JunkEvent::Candidate {
            revision: self.revision,
            current: true,
            historical: false,
            row,
        });
    }
    fn remove(&mut self, key: &str) {
        if let Some(row) = self.rows.remove(key) {
            self.retained = self.retained.saturating_sub(row.retained_bytes());
        }
        self.live_keys.remove(key);
        self.pending.push_back(JunkEvent::Removed {
            revision: self.revision,
            key: key.into(),
        });
    }
    fn selected(&self, keys: &[String]) -> Result<Vec<Arc<Row>>, String> {
        if keys.is_empty()
            || keys.len() > 256
            || keys.iter().collect::<BTreeSet<_>>().len() != keys.len()
        {
            return Err("select 1..256 distinct file rows".into());
        }
        keys.iter()
            .map(|key| {
                self.rows
                    .get(key)
                    .filter(|row| self.live_keys.contains(key) && row.complete() && !row.keeper)
                    .cloned()
                    .ok_or_else(|| {
                        "refresh complete current files; keeper rows cannot be moved".into()
                    })
            })
            .collect()
    }
}
impl JunkProvider for Provider {
    fn presentation(&self) -> ResultPresentation {
        self.options.presentation()
    }
    fn poll(&mut self) -> Option<JunkEvent> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        if let Some(receiver) = &self.trash {
            match receiver.try_recv() {
                Ok((key, result)) => {
                    if result.is_ok() {
                        self.remove(&key);
                    } else {
                        self.complete = false;
                    }
                    return Some(JunkEvent::TrashResult {
                        key,
                        error: result.err(),
                    });
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.trash = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(receiver) = &self.receiver {
            match receiver.try_recv() {
                Ok(Packet::Large(rows)) => {
                    *self.preview.lock().unwrap() = None;
                    let new: BTreeSet<_> = rows.iter().map(|row| row.key.clone()).collect();
                    let evicted: Vec<_> = self.live_keys.difference(&new).cloned().collect();
                    for key in evicted {
                        self.remove(&key);
                    }
                    for row in rows {
                        self.admit(row);
                    }
                }
                Ok(Packet::Group(rows)) => {
                    for row in rows {
                        self.admit(row);
                    }
                }
                Ok(Packet::End(outcome, message)) => {
                    // Cancellation while the reliable terminal packet is waiting still means
                    // this revision cannot authorize mutation, even if native work just ended.
                    let outcome = if self.cancel.is_cancelled() && outcome == JunkOutcome::Complete
                    {
                        JunkOutcome::Cancelled
                    } else {
                        outcome
                    };
                    *self.progress.lock().unwrap() = None;
                    *self.preview.lock().unwrap() = None;
                    self.busy = false;
                    self.complete = outcome == JunkOutcome::Complete && !self.rejected;
                    if self.complete {
                        let obsolete: Vec<_> = self
                            .rows
                            .keys()
                            .filter(|key| !self.live_keys.contains(*key))
                            .cloned()
                            .collect();
                        for key in obsolete {
                            self.remove(&key);
                        }
                    }
                    if !message.is_empty() {
                        self.pending.push_back(JunkEvent::Error {
                            revision: self.revision,
                            message,
                        });
                    }
                    self.pending.push_back(JunkEvent::Completed {
                        revision: self.revision,
                        outcome: if self.rejected {
                            JunkOutcome::Partial
                        } else {
                            outcome
                        },
                        replaced: self.complete,
                    });
                    self.receiver = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.receiver = None;
                    self.busy = false;
                    self.complete = false;
                    self.pending.push_back(JunkEvent::Error {
                        revision: self.revision,
                        message: "analysis disconnected without a terminal result".into(),
                    });
                    self.pending.push_back(JunkEvent::Completed {
                        revision: self.revision,
                        outcome: JunkOutcome::Failed,
                        replaced: false,
                    });
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        let preview = self.preview.lock().unwrap().take();
        if let Some(rows) = preview {
            let new: BTreeSet<_> = rows.iter().map(|row| row.key.clone()).collect();
            let evicted: Vec<_> = self.live_keys.difference(&new).cloned().collect();
            for key in evicted {
                self.remove(&key);
            }
            for row in rows {
                self.admit(row);
            }
            if let Some(event) = self.pending.pop_front() {
                return Some(event);
            }
        }
        let progress = self.progress.lock().unwrap().take();
        if let Some(progress) = progress {
            self.pending.push_back(JunkEvent::Progress {
                revision: self.revision,
                count: progress.count,
                path: progress.path,
            });
            return Some(JunkEvent::Phase {
                revision: self.revision,
                phase: progress.phase,
            });
        }
        None
    }
    fn cancel(&mut self) {
        self.cancel.cancel();
    }
    fn refresh(&mut self, _keys: &[String]) -> Result<(), String> {
        self.start()
    }
    fn prioritize(&mut self, _key: &str) {}
    fn toggle_keeper(&mut self, key: &str) -> Result<(), String> {
        if self.busy || !self.complete || self.trash.is_some() || !self.pending.is_empty() {
            return Err("complete the content analysis and pending updates first".into());
        }
        let row = self.rows.get(key).ok_or("unknown file key")?;
        let group = row
            .group
            .clone()
            .ok_or("keeper selection is for duplicate groups")?;
        let old = self.keepers.remove(&group);
        if old.as_deref() != Some(key) {
            self.keepers.insert(group.clone(), key.into());
        }
        for row in self
            .rows
            .values_mut()
            .filter(|row| row.group.as_ref() == Some(&group))
        {
            let mut updated = (**row).clone();
            updated.keeper = self.keepers.get(&group) == Some(&updated.key);
            *row = Arc::new(updated);
            self.pending.push_back(JunkEvent::Candidate {
                revision: self.revision,
                current: true,
                historical: false,
                row: row.clone(),
            });
        }
        Ok(())
    }
    fn trash(&mut self, keys: &[String]) -> Result<(), String> {
        if self.busy || !self.complete || self.trash.is_some() || !self.pending.is_empty() {
            return Err("complete or refresh the analysis and pending updates first".into());
        }
        let selected = self.selected(keys)?;
        let keepers = selected
            .iter()
            .filter_map(|row| row.group.as_ref())
            .map(|group| {
                self.keepers
                    .get(group)
                    .and_then(|key| self.rows.get(key))
                    .cloned()
                    .ok_or_else(|| {
                        "choose a keeper with p for every selected duplicate group".to_string()
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if keepers.iter().any(|keeper| keys.contains(&keeper.key)) {
            return Err("a selected keeper must remain outside the Trash selection".into());
        }
        let permit = super::junk_tui::mutation_permit()?;
        let options = self.options.clone();
        let (sender, receiver) = sync_channel(1);
        self.cancel = CancellationToken::new();
        let cancel = self.cancel.clone();
        std::thread::Builder::new()
            .name("sweepx-file-trash".into())
            .spawn(move || {
                let _permit = permit;
                let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    preflight(&selected, &keepers, &options, &cancel)
                }))
                .unwrap_or_else(|_| Err("file validation panicked; nothing authorized".into()));
                for row in &selected {
                    let result = match &prepared {
                        Err(error) => Err(error.clone()),
                        Ok(()) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let keeper = row.group.as_ref().and_then(|group| {
                                keepers
                                    .iter()
                                    .find(|keeper| keeper.group.as_ref() == Some(group))
                            });
                            super::trash_command::trash_observed_file(
                                &row.entry,
                                row.stamp.as_ref(),
                                keeper.and_then(|keeper| {
                                    keeper
                                        .stamp
                                        .as_ref()
                                        .map(|stamp| (keeper.entry.as_ref(), stamp))
                                }),
                                &cancel,
                            )
                        }))
                        .unwrap_or_else(|_| Err("Trash worker panicked; outcome unknown".into())),
                    };
                    if sender.send((row.key.clone(), result)).is_err() {
                        break;
                    }
                }
            })
            .map_err(|error| error.to_string())?;
        self.trash = Some(receiver);
        Ok(())
    }
    fn close(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
        self.receiver = None;
        self.trash = None;
        *self.preview.lock().unwrap() = None;
        *self.progress.lock().unwrap() = None;
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.close();
    }
}

fn preflight(
    selected: &[Arc<Row>],
    keepers: &[Arc<Row>],
    options: &Options,
    cancel: &CancellationToken,
) -> Result<(), String> {
    let Options::Duplicates(options) = options else {
        return Ok(());
    };
    let started = Instant::now();
    let deadline = Duration::from_millis(options.max_duration_ms);
    // Recheck the explicit keeper plan inside the worker before any content IO. Neither two
    // selected copies nor a cached/rendered row can silently nominate a surviving object.
    for row in selected {
        let group = row.group.as_ref().ok_or("duplicate group missing")?;
        let keeper = keepers
            .iter()
            .find(|keeper| keeper.group.as_ref() == Some(group))
            .ok_or("explicit keeper missing")?;
        if selected.iter().any(|selected| selected.key == keeper.key) {
            return Err("keeper must survive outside the selection".into());
        }
    }
    let mut unique = BTreeMap::new();
    for row in selected.iter().chain(keepers) {
        unique.insert(row.key.clone(), row);
    }
    let reader = sweepx_scanner::DetailRescanner::new(
        sweepx_scanner::HostPlatformScanner::new(),
        sweepx_platform::ScanResourceLimits::default(),
    );
    for row in unique.values() {
        if cancel.is_cancelled() || started.elapsed() >= deadline {
            return Err("duplicate preflight cancelled or deadline exhausted".into());
        }
        let stamp = row
            .stamp
            .as_ref()
            .ok_or("live content stamp missing; refresh")?;
        reader
            .stream_file(
                sweepx_scanner::FileContentRequest {
                    entry: &row.entry,
                    offset: 0,
                    max_bytes: 0,
                    previous: Some(stamp),
                },
                cancel,
                &mut |_| unreachable!("metadata-only preflight"),
            )
            .map_err(|error| error.to_string())?;
    }
    let remaining = deadline
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or("duplicate preflight deadline exhausted")?;
    let mut bounded = options.clone();
    bounded.max_duration_ms = remaining.as_millis().max(1) as u64;
    let mut collector =
        sweepx_core::DuplicateCollector::new(bounded).map_err(|error| error.to_string())?;
    for row in unique.values() {
        collector.observe(&row.entry);
    }
    let mut reader = reader;
    let report = collector.analyze(&mut reader, true, cancel);
    if !report.complete {
        return Err(format!(
            "duplicate preflight incomplete: {:?}",
            report.incomplete_reasons
        ));
    }
    let mut validated = BTreeMap::new();
    for group in &report.groups {
        for (index, stamp) in group.live_observations.iter().enumerate() {
            let row = Row::new(
                &group.files[index],
                Some((group, index)),
                true,
                Locale::EnUs,
            );
            validated.insert(row.key, (row.group, stamp));
        }
    }
    for row in unique.values() {
        let matching = validated.get(&row.key).is_some_and(|(group, stamp)| {
            group == &row.group && Some(*stamp) == row.stamp.as_ref()
        });
        if !matching {
            return Err(
                "duplicate content, identity or stamp changed; refresh before Trash".into(),
            );
        }
    }
    Ok(())
}

/// Opens the existing terminal list with a background file-analysis provider. The worker owns
/// source observations and cancellation; displayed strings never become execution authority.
pub(crate) fn run(
    context: CoreContext,
    roots: Vec<PathBuf>,
    state_dir: Option<PathBuf>,
    store: Option<DurableSnapshotStore>,
    options: Options,
    unit: HumanSizeUnit,
    sort: ScanSort,
) -> ExitCode {
    let locale = context.locale();
    let provider = match Provider::new(context, ScanRequest { roots, state_dir }, store, options) {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(8);
        }
    };
    match run_junk_browser(locale, unit, sort, provider) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(8)
        }
    }
}

#[cfg(test)]
mod tests;
