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

pub(crate) fn run(
    roots: Vec<PathBuf>,
    locale: Locale,
    unit: HumanSizeUnit,
    sort: ScanSort,
) -> ExitCode {
    let session = match JunkSession::start(JunkSessionRequest::new(roots)) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(8);
        }
    };
    let provider = Provider::new(session);
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
            "risk={} · classification={} · confidence={} · activity={} · blockers={}",
            candidate.risk,
            candidate.classification.as_deref().unwrap_or("not_checked"),
            candidate.confidence.as_deref().unwrap_or("not_checked"),
            candidate.activity.as_deref().unwrap_or("not_checked"),
            candidate.blockers.join(",")
        )
    }
    fn logical_bytes(&self) -> &ByteValue {
        &self.row.aggregate.apparent_logical_bytes
    }
    fn complete(&self) -> bool {
        self.row
            .candidate
            .source_entry
            .as_ref()
            .is_some_and(|entry| entry.coverage.complete && !entry.coverage.details_lost)
            && self.row.aggregate.coverage.complete
            && !self.row.aggregate.coverage.details_lost
    }
    fn retained_bytes(&self) -> usize {
        self.row
            .candidate
            .estimated_retained_bytes()
            .saturating_add(2048)
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
}

// A hung system Trash call must not lead to unbounded new workers in a long-lived CLI process.
static TRASH_WORKER_ACTIVE: AtomicBool = AtomicBool::new(false);
struct TrashPermit;
impl Drop for TrashPermit {
    fn drop(&mut self) {
        TRASH_WORKER_ACTIVE.store(false, Ordering::Release);
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

    fn poll_trash(&mut self) -> Option<JunkEvent> {
        match self.trash.as_ref()?.try_recv() {
            Ok((key, result)) => {
                if result.is_err() {
                    self.historical.insert(key.clone());
                }
                if result.is_ok() {
                    let path = self
                        .rows
                        .get(&key)
                        .and_then(|row| row.row.observed_native_path());
                    // A successfully moved directory also removes its displayed nested candidates.
                    let keys: Vec<_> = self
                        .rows
                        .iter()
                        .filter(|(other, row)| {
                            **other != key
                                && path.as_ref().is_some_and(|path| {
                                    row.row
                                        .observed_native_path()
                                        .is_some_and(|other| other.starts_with(path))
                                })
                        })
                        .map(|(key, _)| key.clone())
                        .collect();
                    for key in keys {
                        self.rows.remove(&key);
                        self.historical.remove(&key);
                        self.pending.push_back(JunkEvent::Removed {
                            revision: self.revision,
                            key,
                        });
                    }
                    self.rows.remove(&key);
                    self.historical.remove(&key);
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
                            JunkSessionPhase::Traversal => "traversal",
                            JunkSessionPhase::Git => "git",
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
                        row,
                    });
                }
                JunkSessionEventKind::Removed { key } => {
                    let key = key.to_string();
                    self.rows.remove(&key);
                    self.historical.remove(&key);
                    return Some(JunkEvent::Removed { revision, key });
                }
                JunkSessionEventKind::Boundary(boundary) => {
                    return Some(JunkEvent::Error {
                        revision,
                        message: format!("{}: {}", boundary.path.display(), boundary.detail),
                    });
                }
                JunkSessionEventKind::Error(error) => {
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
    }
    fn refresh(&mut self, keys: &[String]) -> Result<(), String> {
        if self.busy || self.trash.is_some() {
            return Err("worker busy".into());
        }
        let keys: Vec<_> = self
            .selected(keys)?
            .iter()
            .map(|row| row.native_key)
            .collect();
        self.session
            .refresh_selected(&keys)
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
        if self.busy || !self.complete || self.trash.is_some() {
            return Err("complete the scan or refresh first".into());
        }
        let rows = self.selected(keys)?;
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
        TRASH_WORKER_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "a system Trash worker is still running".to_string())?;
        let permit = TrashPermit;
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
