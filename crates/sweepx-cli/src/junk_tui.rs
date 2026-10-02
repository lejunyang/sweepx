//! Core session to terminal bridge. The UI thread only consumes or enqueues bounded operations.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use sweepx_core::CancellationToken;
use sweepx_core::junk::session::{
    JunkCandidateKey, JunkSession, JunkSessionCandidate, JunkSessionCandidateState,
    JunkSessionEventKind, JunkSessionOutcome, JunkSessionPhase, JunkSessionRequest,
    JunkSessionScope,
};
use sweepx_i18n::Locale;
use sweepx_model::{ByteValue, HumanSizeUnit, ScanSort};
use sweepx_tui::junk::{JunkEvent, JunkOutcome, JunkProvider, JunkRow, run_junk_browser};
#[cfg(target_os = "linux")]
mod quarantine;

pub(crate) fn run(
    roots: Vec<PathBuf>,
    system: bool,
    locale: Locale,
    unit: HumanSizeUnit,
    sort: ScanSort,
    cache_dir: Option<PathBuf>,
    quarantine_base: Option<PathBuf>,
) -> ExitCode {
    #[cfg(not(target_os = "linux"))]
    if quarantine_base.is_some() {
        eprintln!("--quarantine-dir is available only for Linux temporary objects");
        return ExitCode::from(2);
    }
    let mut request = if system {
        JunkSessionRequest::system()
    } else {
        JunkSessionRequest::new(roots)
    };
    request.cache_dir = cache_dir;
    let session = match JunkSession::start(request) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(8);
        }
    };
    let provider = Provider::new(session);
    #[cfg(target_os = "linux")]
    let provider = {
        let mut provider = provider;
        provider.quarantine_base = quarantine_base;
        provider
    };
    match run_junk_browser(locale, unit, sort, provider) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(8)
        }
    }
}

struct Row {
    key: String,
    native_key: JunkCandidateKey,
    revision: u64,
    current: bool,
    preview: bool,
    row: Arc<JunkSessionCandidate>,
}
impl JunkRow for Row {
    fn key(&self) -> &str {
        &self.key
    }
    fn path(&self) -> &str {
        &self.row.candidate.path
    }
    fn rule(&self) -> &str {
        &self.row.candidate.rule_id
    }
    fn evidence(&self) -> &str {
        &self.row.candidate.evidence
    }
    fn context(&self) -> String {
        let candidate = &self.row.candidate;
        format!(
            "risk={} · classification={} · confidence={} · activity={} · format={} · blockers={}",
            candidate.risk,
            candidate.classification.as_deref().unwrap_or("not_checked"),
            candidate.confidence.as_deref().unwrap_or("not_checked"),
            candidate.activity.as_deref().unwrap_or("not_checked"),
            candidate
                .project_format
                .as_ref()
                .map(|e| format!("{}/{}", e.status.code(), e.reason))
                .unwrap_or_else(|| "not_required".into()),
            candidate.blockers.join(",")
        )
    }
    fn logical_bytes(&self) -> &ByteValue {
        self.row.logical_bytes()
    }
    fn complete(&self) -> bool {
        self.row.complete()
    }
    fn report_allows_trash(&self) -> bool {
        self.row.candidate.project_execution_blocker().is_none()
    }
    fn retained_bytes(&self) -> usize {
        self.row.estimated_retained_bytes().saturating_add(2048)
    }
}

struct Provider {
    session: JunkSession,
    rows: BTreeMap<String, Arc<Row>>,
    historical: BTreeSet<String>,
    revision: u64,
    busy: bool,
    complete: bool,
    trash: Option<Receiver<(String, Result<(), String>)>>,
    trash_cancel: CancellationToken,
    pending: VecDeque<JunkEvent>,
    closed: bool,
    #[cfg(target_os = "linux")]
    quarantine: Option<quarantine::Worker>,
    #[cfg(target_os = "linux")]
    quarantine_base: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    quarantine_keys: Vec<String>,
    #[cfg(target_os = "linux")]
    quarantine_operation: u64,
}

// A blocked native mutation must retain the process-wide slot; closing its view cannot authorize
// an unbounded succession of replacement workers. Trash and quarantine share this slot.
static MUTATION_WORKER_ACTIVE: AtomicBool = AtomicBool::new(false);
struct MutationPermit;
impl Drop for MutationPermit {
    fn drop(&mut self) {
        MUTATION_WORKER_ACTIVE.store(false, Ordering::Release);
    }
}

impl Provider {
    fn new(session: JunkSession) -> Self {
        Self {
            session,
            rows: BTreeMap::new(),
            historical: BTreeSet::new(),
            revision: 0,
            busy: true,
            complete: false,
            trash: None,
            trash_cancel: CancellationToken::new(),
            pending: VecDeque::new(),
            closed: false,
            #[cfg(target_os = "linux")]
            quarantine: None,
            #[cfg(target_os = "linux")]
            quarantine_base: None,
            #[cfg(target_os = "linux")]
            quarantine_keys: Vec::new(),
            #[cfg(target_os = "linux")]
            quarantine_operation: 0,
        }
    }

    fn selected(&self, keys: &[String]) -> Result<Vec<Arc<Row>>, String> {
        if keys.is_empty() || keys.len() > 256 {
            return Err("select 1..256 candidates".into());
        }
        keys.iter()
            .map(|key| {
                self.rows
                    .get(key)
                    .cloned()
                    .ok_or_else(|| "unknown candidate key".into())
            })
            .collect()
    }

    fn mutation_busy(&self) -> bool {
        #[cfg(target_os = "linux")]
        if self.quarantine.is_some() {
            return true;
        }
        self.trash.is_some()
    }

    /// Reconciles presentation only, using captured native paths. A confirmed move invalidates
    /// descendant rows and ancestor accounting; it never grants authority for another move.
    fn confirmed_moves(&mut self, moved: &[String]) {
        let paths: Vec<_> = moved
            .iter()
            .filter_map(|key| self.rows.get(key))
            .filter_map(|row| row.row.observed_native_path())
            .collect();
        let removed: Vec<_> = self
            .rows
            .iter()
            .filter(|(key, row)| {
                moved.contains(key)
                    || row
                        .row
                        .observed_native_path()
                        .is_some_and(|path| paths.iter().any(|parent| path.starts_with(parent)))
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in removed {
            self.rows.remove(&key);
            self.historical.remove(&key);
            self.pending.push_back(JunkEvent::Removed {
                revision: self.revision,
                key,
            });
        }
        for (key, row) in &self.rows {
            if row
                .row
                .observed_native_path()
                .is_some_and(|parent| paths.iter().any(|path| path.starts_with(parent.as_path())))
            {
                self.historical.insert(key.clone());
                self.pending.push_back(JunkEvent::Candidate {
                    revision: self.revision,
                    current: row.current,
                    historical: true,
                    row: row.clone(),
                });
            }
        }
    }

    fn poll_trash(&mut self) -> Option<JunkEvent> {
        match self.trash.as_ref()?.try_recv() {
            Ok((key, result)) => {
                if result.is_err() {
                    self.historical.insert(key.clone());
                }
                if result.is_ok() {
                    self.confirmed_moves(std::slice::from_ref(&key));
                }
                Some(JunkEvent::TrashResult {
                    key,
                    error: result.err(),
                })
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.trash = None;
                None
            }
        }
    }
}

impl JunkProvider for Provider {
    fn poll(&mut self) -> Option<JunkEvent> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        #[cfg(target_os = "linux")]
        if let Some(event) = self.poll_quarantine() {
            return Some(event);
        }
        if let Some(event) = self.poll_trash() {
            return Some(event);
        }
        // Statistics have no separate table yet; never let a run of nonvisual events starve input.
        for _ in 0..32 {
            let event = self.session.try_next_event()?;
            let revision = event.revision.get();
            match event.kind {
                JunkSessionEventKind::Started { scope } => {
                    self.revision = revision;
                    self.busy = true;
                    self.complete = false;
                    let keys = match scope {
                        JunkSessionScope::All => None,
                        JunkSessionScope::Selected(keys) => {
                            let paths: Vec<_> = keys
                                .iter()
                                .filter_map(|native| {
                                    self.rows.values().find(|row| row.native_key == *native)
                                })
                                .filter_map(|row| row.row.observed_native_path())
                                .collect();
                            Some(
                                self.rows
                                    .iter()
                                    .filter(|(_, row)| {
                                        row.row.observed_native_path().is_some_and(|path| {
                                            paths.iter().any(|parent| path.starts_with(parent))
                                        })
                                    })
                                    .map(|(key, _)| key.clone())
                                    .collect(),
                            )
                        }
                    };
                    self.historical.extend(
                        keys.as_ref()
                            .cloned()
                            .unwrap_or_else(|| self.rows.keys().cloned().collect()),
                    );
                    return Some(JunkEvent::Started { revision, keys });
                }
                JunkSessionEventKind::Phase(phase) => {
                    return Some(JunkEvent::Phase {
                        revision,
                        phase: match phase {
                            JunkSessionPhase::Rules => "rules",
                            JunkSessionPhase::Discovery => "discovery",
                            JunkSessionPhase::Cache => "cache",
                            JunkSessionPhase::CacheWrite => "cache_write",
                            JunkSessionPhase::Traversal => "traversal",
                            #[cfg(target_os = "linux")]
                            JunkSessionPhase::TemporaryObjects => "temporary_objects",
                            JunkSessionPhase::Git => "git",
                            JunkSessionPhase::Formats => "formats",
                            JunkSessionPhase::Replacement => "replacement",
                        },
                    });
                }
                JunkSessionEventKind::Progress {
                    observed_entries,
                    path,
                } => {
                    return Some(JunkEvent::Progress {
                        revision,
                        count: observed_entries,
                        path: path.display().to_string(),
                    });
                }
                JunkSessionEventKind::Candidate {
                    key, state, row, ..
                } => {
                    let current = state == JunkSessionCandidateState::Current;
                    let row = Arc::new(Row {
                        key: key.to_string(),
                        native_key: key,
                        revision,
                        current,
                        preview: state == JunkSessionCandidateState::Historical,
                        row,
                    });
                    if current {
                        self.historical.remove(&row.key);
                    } else {
                        self.historical.insert(row.key.clone());
                    }
                    self.rows.insert(row.key.clone(), Arc::clone(&row));
                    return Some(JunkEvent::Candidate {
                        revision,
                        current,
                        historical: state == JunkSessionCandidateState::Historical,
                        row,
                    });
                }
                JunkSessionEventKind::Removed { key } => {
                    let key = key.to_string();
                    self.rows.remove(&key);
                    self.historical.remove(&key);
                    return Some(JunkEvent::Removed { revision, key });
                }
                JunkSessionEventKind::Invalidated { key } => {
                    let key = key.to_string();
                    self.historical.insert(key.clone());
                    return Some(JunkEvent::Invalidated { revision, key });
                }
                JunkSessionEventKind::Boundary(boundary) => {
                    return Some(JunkEvent::Error {
                        revision,
                        message: format!("{}: {}", boundary.path.display(), boundary.detail),
                    });
                }
                JunkSessionEventKind::Error(error) | JunkSessionEventKind::CacheWarning(error) => {
                    return Some(JunkEvent::Error {
                        revision,
                        message: format!("{}: {}", error.code, error.detail),
                    });
                }
                JunkSessionEventKind::Completed {
                    outcome, replaced, ..
                } => {
                    self.busy = false;
                    self.complete = outcome == JunkSessionOutcome::Complete && replaced;
                    if !self.complete {
                        self.historical.extend(
                            self.rows
                                .values()
                                .filter(|row| row.revision == revision)
                                .map(|row| row.key.clone()),
                        );
                    }
                    let outcome = match outcome {
                        JunkSessionOutcome::Complete => JunkOutcome::Complete,
                        JunkSessionOutcome::Partial => JunkOutcome::Partial,
                        JunkSessionOutcome::Cancelled => JunkOutcome::Cancelled,
                        JunkSessionOutcome::Failed => JunkOutcome::Failed,
                    };
                    return Some(JunkEvent::Completed {
                        revision,
                        outcome,
                        replaced,
                    });
                }
                JunkSessionEventKind::DirectoryStatistics { .. } => {}
            }
        }
        None
    }

    fn cancel(&mut self) {
        self.session.cancel();
        self.trash_cancel.cancel();
        #[cfg(target_os = "linux")]
        if let Some(worker) = &self.quarantine {
            worker.cancel();
        }
    }
    fn refresh(&mut self, keys: &[String]) -> Result<(), String> {
        if self.busy || self.mutation_busy() {
            return Err("worker busy".into());
        }
        let rows = if keys.is_empty() {
            Vec::new()
        } else {
            self.selected(keys)?
        };
        if keys.is_empty()
            || rows
                .iter()
                .any(|row| row.preview || row.row.directory_aggregate().is_none())
        {
            // Historical preview keys are display state, not the current binding registry.
            // Refresh all original roots so replacement needs fresh complete observations.
            self.session.refresh_all()
        } else {
            self.session
                .refresh_selected(&rows.iter().map(|row| row.native_key).collect::<Vec<_>>())
        }
        .map_err(|error| error.to_string())?;
        self.busy = true;
        self.complete = false;
        Ok(())
    }
    fn prioritize(&mut self, key: &str) {
        let path = self
            .rows
            .get(key)
            .and_then(|row| row.row.observed_native_path());
        let _ = self.session.set_visible_directory(path);
    }
    fn trash(&mut self, keys: &[String]) -> Result<(), String> {
        if self.busy || !self.complete || self.mutation_busy() {
            return Err("complete the scan or refresh first".into());
        }
        let rows = self.selected(keys)?;
        if rows
            .iter()
            .any(|row| row.row.candidate.project_execution_blocker().is_some())
        {
            return Err(
                "project content evidence is report-only; exclusive ownership is unverified".into(),
            );
        }
        if rows
            .iter()
            .any(|row| row.row.directory_aggregate().is_none())
        {
            return Err("Linux temporary objects require x to preview quarantine and type the full plan confirmation".into());
        }
        if rows
            .iter()
            .any(|row| !row.current || self.historical.contains(&row.key) || !row.complete())
        {
            return Err("refresh selected candidates first".into());
        }
        let paths: Vec<_> = rows
            .iter()
            .map(|row| {
                row.row
                    .observed_native_path()
                    .ok_or_else(|| "native path unavailable".to_string())
            })
            .collect::<Result<_, _>>()?;
        if paths.iter().enumerate().any(|(index, path)| {
            paths
                .iter()
                .enumerate()
                .any(|(other, parent)| other != index && path.starts_with(parent))
        }) {
            return Err("selection overlaps; select the ancestor or its descendants".into());
        }
        MUTATION_WORKER_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "a system Trash worker is still running".to_string())?;
        let permit = MutationPermit;
        let (sender, receiver) = sync_channel(1);
        self.trash_cancel = CancellationToken::new();
        let cancel = self.trash_cancel.clone();
        std::thread::Builder::new()
            .name("sweepx-junk-trash".into())
            .spawn(move || {
                let _permit = permit;
                for row in &rows {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        crate::trash_command::trash_session_candidate(&row.row, &cancel)
                    }))
                    .unwrap_or_else(|_| Err("Trash worker panicked; outcome unknown".into()));
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
        if !self.closed {
            self.closed = true;
            self.session.close();
            self.trash_cancel.cancel();
            self.trash = None;
            #[cfg(target_os = "linux")]
            {
                self.quarantine = None;
                self.quarantine_keys.clear();
            }
        }
    }
    #[cfg(target_os = "linux")]
    fn preview_quarantine(&mut self, keys: &[String]) -> Result<u64, String> {
        if self.closed || self.busy || !self.complete || self.mutation_busy() {
            return Err("complete the scan or refresh first; another action may be running".into());
        }
        let rows = self.selected(keys)?;
        if rows
            .iter()
            .any(|row| !row.current || self.historical.contains(&row.key) || !row.complete())
        {
            return Err("refresh selected temporary objects first".into());
        }
        let operation = self
            .quarantine_operation
            .checked_add(1)
            .ok_or("quarantine operation IDs exhausted")?;
        let worker = quarantine::Worker::start(
            operation,
            rows,
            self.quarantine_base.clone(),
            self.complete,
        )?;
        self.quarantine_operation = operation;
        self.quarantine_keys = keys.to_vec();
        self.quarantine = Some(worker);
        Ok(operation)
    }
    #[cfg(target_os = "linux")]
    fn confirm_quarantine(&mut self, operation: u64, answer: &str) -> Result<(), String> {
        self.quarantine
            .as_mut()
            .filter(|worker| worker.operation == operation)
            .ok_or("quarantine preview expired")?
            .confirm(answer)
    }
    #[cfg(target_os = "linux")]
    fn dismiss_quarantine(&mut self, operation: u64) {
        if let Some(worker) = &self.quarantine
            && worker.operation == operation
        {
            worker.cancel();
            if !worker.confirmed {
                self.quarantine = None;
                self.quarantine_keys.clear();
            }
        }
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests;
