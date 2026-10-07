//! Watch scheduling belongs to the existing session worker. Native producers only coalesce
//! bounded invalidations; they never scan, interpret rules, or wait for UI mailbox capacity.

use super::*;
use sweepx_platform::PlatformScanner;
use sweepx_platform::change_monitor::ChangeMonitor;

// Notifications do not report a Windows watched directory's own rename. Periodic root-only
// native admission also detects root replacement/volume changes without enumerating descendants.
pub(super) struct WatchRoot {
    path: PathBuf,
    identity: sweepx_platform::EntryIdentity,
    filesystem: sweepx_platform::FilesystemIdentity,
    mount: sweepx_platform::MountIdentity,
}
impl WatchRoot {
    fn observe(path: &Path, cancel: &CancellationToken) -> Option<Self> {
        let admission = HostPlatformScanner::new()
            .admit_root(&ScanRoot::new(path).ok()?, cancel)
            .ok()?;
        Some(Self {
            path: path.to_path_buf(),
            identity: admission.metadata.identity?,
            filesystem: admission.metadata.filesystem_identity?,
            mount: admission.metadata.mount_identity?,
        })
    }
    fn matches(&self, other: &Self) -> bool {
        self.path == other.path
            && self.identity == other.identity
            && self.filesystem == other.filesystem
            && self.mount == other.mount
    }
}

impl Worker {
    pub(super) fn stop_monitor(&mut self) {
        if let Some(monitor) = self.monitor.take() {
            monitor.wait_for_exit();
        }
    }

    pub(super) fn prepare_monitor(
        &mut self,
        job: &Job,
        writer: &mut Writer,
    ) -> Result<(), JunkSessionFailure> {
        if self.request.watch
            && !self.watch_disabled
            && !self.scan_roots.is_empty()
            && (self.monitor.is_none() || (job.selected.is_none() && job.paths.is_none()))
        {
            // A complete scan rebuilds subscriptions after gaps or root replacement. Installation
            // precedes observations; no event drain occurs after traversal to hide racing writes.
            self.stop_monitor();
            self.watch_roots = self
                .scan_roots
                .iter()
                .map(|path| WatchRoot::observe(path, &job.cancel))
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default();
            let startup = if self.watch_roots.len() == self.scan_roots.len() {
                ChangeMonitor::start(&self.scan_roots, self.request.watch_limits)
            } else {
                Err(std::io::Error::other(
                    "native notification root binding unavailable",
                ))
            };
            self.watch_checked = std::time::Instant::now();
            match startup {
                Ok(monitor) => self.monitor = Some(Arc::new(monitor)),
                Err(error) => {
                    self.watch_disabled = true;
                    self.watch_warning = Some(error.to_string());
                }
            }
        }
        if let Some(detail) = self.watch_warning.take() {
            writer.send(JunkSessionEventKind::WatchWarning(JunkSessionFailure::new(
                "watch_unavailable",
                detail,
            )))?;
        }
        Ok(())
    }

    pub(super) fn next_job(&mut self, shared: &Shared) -> Option<Job> {
        if !self.request.watch {
            return shared.next_job();
        }
        loop {
            if let Some(job) = shared.next_job_timeout(Duration::from_millis(100)) {
                return Some(job);
            }
            if shared.lock().closed {
                return None;
            }
            if self.monitor.is_some()
                && self.watch_checked.elapsed() >= Duration::from_secs(1)
                && !shared.cancel_token().is_cancelled()
            {
                self.watch_checked = std::time::Instant::now();
                let cancel = shared.cancel_token();
                if self.watch_roots.iter().any(|root| {
                    WatchRoot::observe(&root.path, &cancel)
                        .is_none_or(|current| !root.matches(&current))
                }) && let Some(monitor) = &self.monitor
                {
                    monitor.report_gap();
                }
            }
            if let Some(monitor) = &self.monitor
                && let Some((job, failure)) = shared.watch_job(monitor)
            {
                if let Some(detail) = failure {
                    // One complete fallback revision reports the failure. Do not loop on a
                    // permanently broken watcher or pretend idle polling proves freshness.
                    self.watch_disabled = true;
                    self.watch_warning = Some(detail);
                    self.stop_monitor();
                }
                return Some(job);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_gaps_remain_pending_behind_terminals_and_operation_pauses() {
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = std::fs::canonicalize(fixture.path()).unwrap();
        #[cfg(not(unix))]
        let root = fixture.path().to_path_buf();
        let monitor = ChangeMonitor::start(&[root], Default::default()).unwrap();
        let shared = Arc::new(Shared::new(JunkSessionLimits::default()));
        let writer = Writer::new(
            Arc::clone(&shared),
            JunkSessionRevision(1),
            shared.cancel_token(),
        );
        monitor.report_gap();
        writer.finish(JunkSessionOutcome::Complete, true, 0);
        assert!(shared.watch_job(&monitor).is_none());
        shared.pop().unwrap();
        let pause = shared.suspend_auto_refresh().unwrap();
        assert!(shared.watch_job(&monitor).is_none());
        drop(pause);
        let (job, failure) = shared.watch_job(&monitor).unwrap();
        assert_eq!(job.revision, JunkSessionRevision(2));
        assert!(job.paths.is_none() && failure.is_none());
        monitor.report_gap();
        assert!(shared.watch_job(&monitor).is_none());
        let writer = Writer::new(Arc::clone(&shared), job.revision, job.cancel);
        writer.finish(JunkSessionOutcome::Complete, true, 0);
        shared.pop().unwrap();
        assert_eq!(
            shared.watch_job(&monitor).unwrap().0.revision,
            JunkSessionRevision(3)
        );
        monitor.wait_for_exit();
        shared.close();
    }
}
