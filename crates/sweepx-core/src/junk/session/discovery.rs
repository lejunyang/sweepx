//! Optional probes overlap native traversal. One bounded task per session; a separate permit
//! caps detached tasks too, so a slow OS call cannot create unlimited workers across sessions.
use super::*;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
static ACTIVE_PROBES: AtomicUsize = AtomicUsize::new(0);
struct ProbePermit;
impl Drop for ProbePermit {
    fn drop(&mut self) {
        ACTIVE_PROBES.fetch_sub(1, Ordering::AcqRel);
    }
}
struct DiscoveryTask {
    receiver: Receiver<Result<PlatformJunkSetup, String>>,
    cancel: CancellationToken,
    finished: bool,
}
impl DiscoveryTask {
    fn start(ids: Vec<String>, cancel: CancellationToken) -> Result<Self, String> {
        ACTIVE_PROBES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_SESSIONS).then_some(n + 1)
            })
            .map_err(|_| "optional tool workers are still stopping".to_string())?;
        let permit = ProbePermit;
        let (tx, receiver) = sync_channel(1);
        let token = cancel.clone();
        std::thread::Builder::new()
            .name("junk-tool-settings".into())
            .spawn(move || {
                let _permit = permit;
                let result = PlatformJunkSetup::discover_selected_with_cancel(&ids, token);
                let _ = tx.send(result);
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            receiver,
            cancel,
            finished: false,
        })
    }
    fn receive(&mut self) -> Result<PlatformJunkSetup, String> {
        loop {
            if self.cancel.is_cancelled() {
                return Err("cancelled".into());
            }
            match self.receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => {
                    self.finished = true;
                    return result;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.finished = true;
                    return Err("optional tool worker exited".into());
                }
            }
        }
    }
}
impl Drop for DiscoveryTask {
    fn drop(&mut self) {
        if !self.finished {
            self.cancel.cancel();
        }
    }
}
impl Worker {
    pub(super) fn run_progressive(
        &mut self,
        job: &Job,
        writer: &mut Writer,
        ids: Vec<String>,
    ) -> Result<(), JunkSessionFailure> {
        let task = DiscoveryTask::start(ids.clone(), job.cancel.clone());
        self.run_progressive_with(
            job,
            writer,
            |cancel| PlatformJunkSetup::discover_known_with_cancel(&ids, cancel),
            || task.and_then(|mut task| task.receive()),
        )
    }

    // The injected completion gate lets tests prove first results precede optional queries without
    // depending on wall-clock sleeps or on the host's installed package managers.
    pub(super) fn run_progressive_with(
        &mut self,
        job: &Job,
        writer: &mut Writer,
        known_discovery: impl FnOnce(CancellationToken) -> Result<PlatformJunkSetup, String>,
        finish_discovery: impl FnOnce() -> Result<PlatformJunkSetup, String>,
    ) -> Result<(), JunkSessionFailure> {
        writer.defer_terminal = true;
        let system = self.request.system;
        let mut known = Vec::new();
        let first = self.run_with_discovery(job, writer, |cancel| {
            let setup = known_discovery(cancel)?;
            known = default_platform_junk_roots(&setup);
            Ok((setup, if system { known.clone() } else { Vec::new() }))
        });
        if first.is_err() || job.cancel.is_cancelled() {
            writer.defer_terminal = false;
            return first.and_then(|_| Err(JunkSessionFailure::new("cancelled", "scan stopped")));
        }
        let first_outcome = writer
            .deferred
            .borrow_mut()
            .take()
            .map(|v| v.0)
            .unwrap_or(JunkSessionOutcome::Failed);
        writer.phase(JunkSessionPhase::Supplementary)?;
        let setup = match finish_discovery() {
            Ok(setup) => setup,
            Err(message) => {
                writer.defer_terminal = false;
                if job.cancel.is_cancelled() {
                    return Err(JunkSessionFailure::new("cancelled", "scan stopped"));
                }
                writer.send(JunkSessionEventKind::ToolQueryWarning(
                    JunkSessionFailure::new("tool_query_failed", message),
                ))?;
                writer.finish(
                    first_outcome,
                    first_outcome == JunkSessionOutcome::Complete,
                    self.current.len(),
                );
                return Ok(());
            }
        };
        let all = default_platform_junk_roots(&setup);
        let extras: Vec<_> = all
            .iter()
            .filter(|path| {
                !known.contains(path)
                    && (system || self.scan_roots.iter().any(|root| path.starts_with(root)))
            })
            .cloned()
            .collect();
        // Updating a tool's configured location never upgrades current filesystem facts or
        // wipes independently observed formats/Git. These fields only describe configuration.
        let rules_digest = self.loaded_rules_digest();
        for (key, row) in &mut self.current {
            let candidate = &mut Arc::make_mut(row).candidate;
            if let Some(rule) = setup.rules.iter().find(|rule| rule.id == candidate.rule_id)
                && let Some(entry) = &candidate.source_entry
                && super::super::platform::tool_reported_root_for(&rule.root_kind).is_some()
            {
                candidate.activity = Some(
                    super::super::platform::classify_tool_root(rule, entry, &setup.evidence)
                        .unwrap_or(super::super::platform::ToolRootActivity::Unknown)
                        .code()
                        .into(),
                );
                candidate.stale_formats = super::super::platform::superseded_format_generations(
                    rule,
                    entry,
                    &setup.evidence,
                );
                // This row was already published as current by the native pass. History omitted
                // by a partial pass must never be upgraded by the optional probe.
                if candidate.source_entry.as_ref().is_some_and(|entry| {
                    entry.scan_id.as_ref() == format!("{}:{}", self.session_id, job.revision.0)
                }) {
                    self.presentations.send_candidate(
                        writer,
                        self.request.limits,
                        *key,
                        JunkSessionCandidateState::Current,
                        rules_digest,
                        row.clone(),
                    )?;
                }
            }
        }
        if extras.is_empty() {
            if let Some(reason) = setup.evidence.layout_failure() {
                writer.failure(JunkSessionFailure::new(
                    "layout_discovery_incomplete",
                    reason.code(),
                ));
            }
            self.send_tool_warnings(&setup, writer)?;
        } else {
            if system {
                let mut scope = self.scan_roots.clone();
                scope.extend(extras.clone());
                self.scan_roots = normalize_discovered_roots(scope)?;
            }
            writer.supplementary_pass = true;
            let supplemental = Job {
                revision: job.revision,
                selected: None,
                paths: Some(extras),
                cancel: job.cancel.clone(),
            };
            let result = self.run_with_discovery(&supplemental, writer, |_| Ok((setup, all)));
            writer.supplementary_pass = false;
            if let Err(error) = result {
                writer.defer_terminal = false;
                return Err(error);
            }
        }
        let next = writer
            .deferred
            .borrow_mut()
            .take()
            .map(|v| v.0)
            .unwrap_or(JunkSessionOutcome::Complete);
        writer.defer_terminal = false;
        let outcome = if job.cancel.is_cancelled() {
            JunkSessionOutcome::Cancelled
        } else if next == JunkSessionOutcome::Failed {
            next
        } else if first_outcome != JunkSessionOutcome::Complete
            || next != JunkSessionOutcome::Complete
            || writer.error_count > 0
            || writer.coverage_incomplete
        {
            JunkSessionOutcome::Partial
        } else {
            JunkSessionOutcome::Complete
        };
        writer.finish(
            outcome,
            outcome == JunkSessionOutcome::Complete,
            self.current.len(),
        );
        Ok(())
    }
    pub(super) fn send_tool_warnings(
        &self,
        platform: &PlatformJunkSetup,
        writer: &mut Writer,
    ) -> Result<(), JunkSessionFailure> {
        for (rule, detail) in platform.evidence.cache_query_failures() {
            writer.send(JunkSessionEventKind::ToolQueryWarning(
                JunkSessionFailure::new("tool_query_failed", format!("{detail} ({rule})")),
            ))?;
        }
        if let Some(reason) = platform.evidence.tool_discovery_failure() {
            writer.send(JunkSessionEventKind::ToolQueryWarning(
                JunkSessionFailure::new(
                    "npm_discovery_incomplete",
                    format!(
                        "{}: {}",
                        reason.code(),
                        platform
                            .evidence
                            .tool_discovery_detail()
                            .unwrap_or("npm installation discovery could not complete")
                    ),
                ),
            ))?;
        }
        Ok(())
    }
}
