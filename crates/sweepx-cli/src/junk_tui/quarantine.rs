//! One worker retains the native preview across human review. No native work runs on the UI thread.

use super::*;
use std::sync::mpsc::{SyncSender, TryRecvError};
use std::time::{Duration, Instant};
use sweepx_core::junk::quarantine::{self, TempCleanInput, TempCleanPreview};

pub(super) enum WorkerEvent {
    Preview {
        digest: String,
        plan: String,
    },
    Finished {
        moved: Vec<String>,
        message: String,
        failed: bool,
    },
}
pub(super) struct Worker {
    pub operation: u64,
    pub events: Receiver<WorkerEvent>,
    commands: SyncSender<String>,
    cancel: CancellationToken,
    pub ready: bool,
    pub confirmed: bool,
}
impl Worker {
    pub fn start(
        operation: u64,
        rows: Vec<Arc<Row>>,
        base: Option<PathBuf>,
        complete: bool,
        pause: JunkAutoRefreshPause,
    ) -> Result<Self, String> {
        // This is presentation/native-fact selection only. The worker performs independent
        // preview validation, and the original measurement must match even for equal-size swaps.
        let inputs = rows
            .iter()
            .map(|row| {
                let sweepx_core::junk::session::JunkSessionFacts::LinuxTemporary {
                    measurement,
                    ..
                } = &row.row.facts
                else {
                    return Err(
                        "select temporary objects only; directory candidates use d/Delete Trash"
                            .to_string(),
                    );
                };
                Ok(TempCleanInput {
                    path: row
                        .row
                        .candidate
                        .native_path
                        .clone()
                        .ok_or("native temporary path unavailable")?,
                    allocated_bytes: measurement.allocated_bytes,
                    expected: Some(Arc::clone(measurement)),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        MUTATION_WORKER_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "a filesystem mutation worker is still running".to_string())?;
        let permit = MutationPermit;
        let cancel = CancellationToken::new();
        let worker_cancel = cancel.clone();
        let (sender, events) = sync_channel(1);
        let (commands, receiver) = sync_channel::<String>(1);
        std::thread::Builder::new().name("sweepx-junk-quarantine".into()).spawn(move || {
            let _permit = permit;
            let _pause = pause;
            let mut recovery = None;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<WorkerEvent, String> {
                let preview = quarantine::preview_temp_clean(&inputs, base.as_deref(), complete, &worker_cancel)?;
                recovery = Some(format!("{}/linux-temp-{}", preview.plan().quarantine_base.trim_end_matches('/'), &preview.digest()[..16]));
                let plan = display_plan(&preview)?;
                sender.send(WorkerEvent::Preview { digest: preview.digest().into(), plan })
                    .map_err(|_| "view closed before confirmation".to_string())?;
                // A retained preview has bounded resources and one command slot. Closing the view
                // drops both channels and cancels, without joining a blocked native call.
                let deadline = Instant::now() + Duration::from_secs(900);
                let answer = loop {
                    if worker_cancel.is_cancelled() { return Err("quarantine cancelled before execution".into()); }
                    if Instant::now() >= deadline { return Err("quarantine confirmation expired; preview again".into()); }
                    match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok(answer) => break answer,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err("quarantine preview dismissed".into()),
                    }
                };
                let result = quarantine::execute_temp_clean(preview, &answer, &worker_cancel)?;
                let moved = result.moved.iter().filter_map(|(source, _, _)| rows.iter()
                    .find(|row| row.row.candidate.native_path.as_ref() == Some(source))
                    .map(|row| row.key.clone())).collect();
                let failed = result.failure.is_some();
                let message = format!("Quarantined {} selected objects.\nRecovery directory: {}\nPlan digest: {}\n{}",
                    result.moved.len(), result.recovery_directory.display(), result.digest,
                    result.failure.map_or_else(|| "Complete; recovery material retained.".into(), |(path, error)|
                        format!("Stopped: {}: {error}\nA partial source and recovery copy may remain.", path.display())));
                Ok(WorkerEvent::Finished { moved, message, failed })
            })).unwrap_or_else(|_| Err("quarantine worker panicked; outcome unknown".into()));
            let event = result.unwrap_or_else(|error| WorkerEvent::Finished {
                moved: Vec::new(), failed: true,
                message: format!("{error}\nRecovery location, if created: {}\nRefresh affected objects before another action.", recovery.as_deref().unwrap_or("not prepared")),
            });
            let _ = sender.send(event);
        }).map_err(|error| error.to_string())?;
        Ok(Self {
            operation,
            events,
            commands,
            cancel,
            ready: false,
            confirmed: false,
        })
    }
    pub fn confirm(&mut self, answer: &str) -> Result<(), String> {
        if !self.ready || self.confirmed || answer.len() > 160 || self.cancel.is_cancelled() {
            return Err("quarantine preview is unavailable or already confirmed".into());
        }
        self.commands
            .try_send(answer.into())
            .map_err(|_| "quarantine worker is unavailable".to_string())?;
        self.confirmed = true;
        Ok(())
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn display_plan(preview: &TempCleanPreview) -> Result<String, String> {
    use std::fmt::Write;
    let plan = preview.plan();
    let mut text = format!(
        "Planned recovery directory: {}\nPlan digest: {}\nMode: recoverable cross-filesystem quarantine\nMinimum idle seconds: {}\nRule bytes digest: {}\nReference view: {}\nRemaining blockers: {}\n",
        serde_json::to_string(&format!(
            "{}/linux-temp-{}",
            plan.quarantine_base.trim_end_matches('/'),
            &preview.digest()[..16]
        ))
        .map_err(|error| error.to_string())?,
        preview.digest(),
        plan.minimum_idle_seconds,
        plan.rule_bytes_digest,
        plan.process_observation,
        plan.blockers.join(",")
    );
    if std::str::from_utf8(&plan.quarantine_base_bytes).is_err()
        || plan
            .quarantine_base_bytes
            .iter()
            .any(|byte| byte.is_ascii_control())
    {
        text.push_str("Recovery base native hex: ");
        for byte in &plan.quarantine_base_bytes {
            write!(&mut text, "{byte:02x}").map_err(|error| error.to_string())?;
        }
        text.push('\n');
    }
    for item in &plan.candidates {
        let path = serde_json::to_string(&item.path).map_err(|error| error.to_string())?;
        let row = format!(
            "\n{path} [{}]\n  logical={} allocated={} entries={}\n  device={} inode={} ownerUid={} ownerGid={} mode={:o}\n  modified={}.{:09} changed={}.{:09}\n  recursiveAccess={}.{:09} recursiveActivity={}.{:09}\n",
            item.inode_type,
            item.logical_bytes,
            item.allocated_bytes,
            item.entry_count,
            item.device,
            item.inode,
            item.owner_uid,
            item.owner_gid,
            item.mode,
            item.modified_unix_seconds,
            item.modified_nanoseconds,
            item.status_change_unix_seconds,
            item.status_change_nanoseconds,
            item.recursive_last_access_seconds,
            item.recursive_last_access_nanoseconds,
            item.recursive_last_activity_seconds,
            item.recursive_last_activity_nanoseconds
        );
        if text
            .len()
            .saturating_add(row.len())
            .saturating_add(item.path_bytes.len().saturating_mul(2))
            .saturating_add(32)
            > 1024 * 1024
        {
            return Err(
                "complete quarantine plan exceeds display budget; select fewer objects".into(),
            );
        }
        text.push_str(&row);
        if std::str::from_utf8(&item.path_bytes).is_err()
            || item.path_bytes.iter().any(|byte| byte.is_ascii_control())
        {
            text.push_str("  nativePathHex=");
            for byte in &item.path_bytes {
                write!(&mut text, "{byte:02x}").map_err(|error| error.to_string())?;
            }
            text.push('\n');
        }
    }
    Ok(text)
}

impl Provider {
    pub(super) fn poll_quarantine(&mut self) -> Option<JunkEvent> {
        let worker = self.quarantine.as_mut()?;
        let operation = worker.operation;
        match worker.events.try_recv() {
            Ok(WorkerEvent::Preview { digest, plan }) => {
                worker.ready = true;
                Some(JunkEvent::QuarantinePreview {
                    operation,
                    digest,
                    plan,
                })
            }
            Ok(WorkerEvent::Finished {
                moved,
                message,
                failed,
            }) => {
                self.quarantine = None;
                self.auto_pause = None;
                self.confirmed_moves(&moved);
                self.historical.extend(
                    self.quarantine_keys
                        .iter()
                        .filter(|key| !moved.contains(key) && self.rows.contains_key(*key))
                        .cloned(),
                );
                self.quarantine_keys.clear();
                Some(JunkEvent::QuarantineFinished {
                    operation,
                    moved,
                    message,
                    failed,
                })
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.quarantine = None;
                self.auto_pause = None;
                self.historical.extend(
                    std::mem::take(&mut self.quarantine_keys)
                        .into_iter()
                        .filter(|key| self.rows.contains_key(key)),
                );
                Some(JunkEvent::QuarantineFinished {
                    operation,
                    moved: Vec::new(),
                    message: "quarantine worker disconnected; outcome unknown".into(),
                    failed: true,
                })
            }
        }
    }
}
