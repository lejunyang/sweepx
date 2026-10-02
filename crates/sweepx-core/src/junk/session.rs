//! Worker-owned explicit/system junk scans. No terminal rendering, mutation or durable UI journal.
//!
//! Reliable events apply backpressure; consumers must keep draining after cancellation or close
//! the session. Progress/statistics are coalesced. Drop closes the queue and cancels native work
//! without joining on the UI thread: blocking OS calls remain cooperative, not interruptible.

#[cfg(target_os = "macos")]
mod cache;
#[cfg(target_os = "linux")]
mod linux_temp;
mod mailbox;
mod presentation;

use super::candidate::JunkCandidate;
use super::git::{GitEvidenceLimits, GitEvidenceSession, native_path, native_root_path};
use super::platform::{PlatformJunkSetup, default_platform_junk_roots};
use super::{JunkService, PROJECT_RULES_JSON};
use mailbox::{Shared, Writer};
use presentation::PresentationIndex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use sweepx_model::{
    DirectoryAggregate, IdentityEvidence, ScanId, ScanObjectIdentity, ScannedEntry,
};
use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot};
use sweepx_scanner::{
    ClassifiedScanObserver, DetailRescanRequest, DetailRescanner, HostPlatformScanner,
    ProgressEvent, Scanner, ScannerOptions,
};

const MAX_SESSIONS: usize = 4;
const MAX_ROOTS: usize = 256;
const MAX_SELECTION: usize = 256;
static ACTIVE_SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// Stable presentation key for a lossless observed path, native object and admitted rule ID.
/// Scan IDs, content fingerprints and revisions are deliberately separate. This is not authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JunkCandidateKey([u8; 32]);

impl std::fmt::Display for JunkCandidateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Monotonically increasing job revision within a session; a new scan ID is issued per revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct JunkSessionRevision(u64);
impl JunkSessionRevision {
    /// Returns the revision number, starting at one.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Scope whose old evidence must be marked historical until this revision completes.
#[derive(Debug, Clone)]
pub enum JunkSessionScope {
    /// Entire observation scope; a full system revision rediscovers its roots.
    All,
    /// Native candidate subtrees, identified by keys from this session.
    Selected(Arc<[JunkCandidateKey]>),
}

/// Worker phase; traversal completion is not session completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JunkSessionPhase {
    Rules,
    Discovery,
    /// Historical preview reads and file-index change-history validation.
    Cache,
    /// Best-effort publication of freshly observed filesystem facts.
    CacheWrite,
    Traversal,
    /// Current bounded content observations, including validated filesystem-cache rows.
    Formats,
    /// Native Linux temporary-object measurement and current-user reference observations.
    #[cfg(target_os = "linux")]
    TemporaryObjects,
    Git,
    Replacement,
}

/// Status of a candidate observation within a revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JunkSessionCandidateState {
    /// Historical cache preview; no current interpretation or mutation authority.
    Historical,
    /// Base rule and final traversal statistics; current Git interpretation is still pending.
    Base,
    /// Interpretation finished for this revision; may include explicit unknown evidence/blockers.
    Current,
}

/// Facts retained for a candidate, without promoting one observation contract into another.
#[derive(Debug, Clone)]
pub enum JunkSessionFacts {
    /// Traversal statistics for a native directory candidate.
    Directory(Box<DirectoryAggregate>),
    /// Independent temporary-object facts; not a generic directory locator or Trash authority.
    #[cfg(target_os = "linux")]
    LinuxTemporary {
        /// Shared recursive identity and activity observations; selection must not deep-copy them on
        /// the UI thread. Native previews independently reobserve and compare these facts.
        measurement: Arc<super::linux_temp::LinuxTempMeasurement>,
        /// Logical file bytes, distinct from the report's allocation evidence.
        logical_bytes: sweepx_model::ByteValue,
    },
}

/// Shared report and typed facts from one fresh observation.
#[derive(Debug, Clone)]
pub struct JunkSessionCandidate {
    /// Report-only interpretation, including the current native source row.
    pub candidate: JunkCandidate,
    /// Directory traversal or independent temporary-object facts, never interchangeable.
    pub facts: JunkSessionFacts,
}
impl JunkSessionCandidate {
    /// Returns directory statistics only for directory observations.
    pub fn directory_aggregate(&self) -> Option<&DirectoryAggregate> {
        match &self.facts {
            JunkSessionFacts::Directory(aggregate) => Some(aggregate),
            #[cfg(target_os = "linux")]
            JunkSessionFacts::LinuxTemporary { .. } => None,
        }
    }

    /// Logical bytes for display; allocation and reclaimable evidence remain separate.
    pub fn logical_bytes(&self) -> &sweepx_model::ByteValue {
        match &self.facts {
            JunkSessionFacts::Directory(aggregate) => &aggregate.apparent_logical_bytes,
            #[cfg(target_os = "linux")]
            JunkSessionFacts::LinuxTemporary { logical_bytes, .. } => logical_bytes,
        }
    }

    /// Whether observed facts are complete, independent of any later execution permission.
    pub fn complete(&self) -> bool {
        match &self.facts {
            JunkSessionFacts::Directory(aggregate) => {
                self.candidate
                    .source_entry
                    .as_ref()
                    .is_some_and(|entry| entry.coverage.complete && !entry.coverage.details_lost)
                    && aggregate.coverage.complete
                    && !aggregate.coverage.details_lost
            }
            #[cfg(target_os = "linux")]
            JunkSessionFacts::LinuxTemporary { .. } => !self
                .candidate
                .blockers
                .iter()
                .any(|blocker| blocker == "linux_tmp_discovery_incomplete"),
        }
    }

    /// Lossless observed path for presentation and scope comparison, decoded with fixed bounds.
    /// It never authorizes reopening or deletion; native binding checks remain independent.
    pub fn observed_native_path(&self) -> Option<PathBuf> {
        match &self.facts {
            JunkSessionFacts::Directory(_) => native_path(self.candidate.source_entry.as_ref()?),
            #[cfg(target_os = "linux")]
            JunkSessionFacts::LinuxTemporary { .. } => self.candidate.native_path.clone(),
        }
    }

    /// Revalidates the captured directory chain with no-follow object/filesystem/mount checks.
    /// Run on a worker immediately before a separate native action. This read-only observation
    /// is not an execution permit and does not make a later pathname mutation atomic.
    pub fn revalidate_native_binding(
        &self,
        cancel: &CancellationToken,
        limits: ScanResourceLimits,
    ) -> Result<(), JunkSessionFailure> {
        if self.directory_aggregate().is_none() {
            return Err(JunkSessionFailure::new(
                "temporary_requires_quarantine",
                "temporary objects require independent quarantine preview",
            ));
        }
        validate_directory_binding(self, cancel, limits)
    }

    /// Conservative retained-data estimate including typed native facts; not allocator RSS.
    pub fn estimated_retained_bytes(&self) -> usize {
        let facts = match &self.facts {
            JunkSessionFacts::Directory(aggregate) => aggregate
                .scan_id
                .len()
                .saturating_add(aggregate.directory_identity.capacity())
                .saturating_add(
                    aggregate
                        .coverage
                        .incomplete_reasons
                        .capacity()
                        .saturating_mul(std::mem::size_of::<sweepx_model::ReasonCode>()),
                ),
            #[cfg(target_os = "linux")]
            JunkSessionFacts::LinuxTemporary { measurement, .. } => {
                measurement.entries.keys().fold(
                    1024usize.saturating_add(measurement.fifo_inodes.len().saturating_mul(64)),
                    |sum, path| sum.saturating_add(256).saturating_add(path.capacity()),
                )
            }
        };
        self.candidate
            .estimated_retained_bytes()
            .saturating_add(1024)
            .saturating_add(facts)
    }

    fn cost(&self) -> usize {
        self.estimated_retained_bytes()
    }
}

/// Result of a revision, distinct from progress and unknown Git evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JunkSessionOutcome {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

/// Bounded diagnostic from admission, traversal, refresh validation or the worker itself.
#[derive(Debug, Clone)]
pub struct JunkSessionFailure {
    /// Stable machine code; never localized.
    pub code: &'static str,
    /// Diagnostic text, capped at 2 KiB; truncation is explicitly indicated.
    pub detail: String,
}
impl JunkSessionFailure {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        let mut detail = detail.into();
        if detail.len() > 2048 {
            let mut end = 2000;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
            detail.push_str(" [diagnostic truncated]");
        }
        Self { code, detail }
    }
}

/// Event payload. Base/current updates share a stable key; completion explicitly commits removal.
#[derive(Debug, Clone)]
pub enum JunkSessionEventKind {
    /// Begin replacement of a scope; existing UI evidence in this scope becomes historical.
    Started { scope: JunkSessionScope },
    /// Worker advanced to the next phase.
    Phase(JunkSessionPhase),
    /// Coalesced traversal count and current presentation path; never execution authority.
    Progress {
        observed_entries: u64,
        path: PathBuf,
    },
    /// Coalesced lower-bound batch statistics; final values arrive in candidate observations.
    DirectoryStatistics {
        path: PathBuf,
        aggregate: Box<DirectoryAggregate>,
    },
    /// A retained base or current candidate. Source facts keep the current scan identity.
    Candidate {
        key: JunkCandidateKey,
        state: JunkSessionCandidateState,
        rules_digest: [u8; 32],
        row: Arc<JunkSessionCandidate>,
    },
    /// Remove an old scoped key only after fresh observations proved complete replacement.
    Removed { key: JunkCandidateKey },
    /// Retain a prior row as historical. Its binding remains available for selected refresh,
    /// but ancestor accounting or interpretation has not been recomputed in this revision.
    Invalidated { key: JunkCandidateKey },
    /// A filesystem boundary, including resource/permission failures; never silently dropped.
    Boundary(Box<sweepx_platform::BoundaryRecord>),
    /// A reliable diagnostic; completion follows with an explicit outcome.
    Error(JunkSessionFailure),
    /// Optional cache failure; fresh scan validity is unaffected.
    CacheWarning(JunkSessionFailure),
    /// Final event for the revision, delivered after every queued reliable observation.
    Completed {
        outcome: JunkSessionOutcome,
        replaced: bool,
        candidate_count: usize,
        error_count: usize,
    },
}

/// One revision-bound event. Consumers must not apply an older revision over newer evidence.
#[derive(Debug, Clone)]
pub struct JunkSessionEvent {
    /// Revision that produced the event, independent of each row's scan ID.
    pub revision: JunkSessionRevision,
    /// Observation or lifecycle change.
    pub kind: JunkSessionEventKind,
}

/// Explicit bounds for session storage and the underlying native traversal.
#[derive(Debug, Clone, Copy)]
pub struct JunkSessionLimits {
    /// Maximum reliable queued events, excluding two coalescing slots and one terminal slot.
    pub max_events: usize,
    /// Estimated queued payload bytes, including referenced candidate data conservatively.
    pub max_event_bytes: usize,
    /// Maximum rows across old retained state and the pending revision together. Separately caps
    /// distinct presentation keys retained across revisions, including cancelled Base previews.
    pub max_candidates: usize,
    /// Estimated bytes across old retained state and the pending revision together; not RSS.
    /// Also independently caps the display-only native path index, not consumer row payloads.
    pub max_candidate_bytes: usize,
    /// Existing scanner's metadata, handle, frontier and enumeration limits.
    pub scan: ScanResourceLimits,
    /// Current Git observation and subprocess limits, renewed for each revision.
    pub git: GitEvidenceLimits,
    /// Current project content observations, renewed for every revision.
    pub formats: super::format::ProjectFormatLimits,
    /// Shared native temporary-object budgets for one full Linux system revision.
    #[cfg(target_os = "linux")]
    pub linux_temp: super::linux_temp::LinuxTempObservationLimits,
}
impl Default for JunkSessionLimits {
    fn default() -> Self {
        Self {
            max_events: 64,
            max_event_bytes: 8 * 1024 * 1024,
            max_candidates: 16_384,
            max_candidate_bytes: 64 * 1024 * 1024,
            scan: ScanResourceLimits::default(),
            git: GitEvidenceLimits::default(),
            formats: super::format::ProjectFormatLimits::default(),
            #[cfg(target_os = "linux")]
            linux_temp: super::linux_temp::LinuxTempObservationLimits::default(),
        }
    }
}

/// Inputs for explicit directory roots or worker-discovered system junk analysis.
pub struct JunkSessionRequest {
    /// Absolute user-selected roots; normalized without following or collapsing linked ancestors.
    pub roots: Vec<PathBuf>,
    /// Discover conservative platform roots each full revision; requires empty explicit roots
    /// and platform rules. Linux temporary objects use independent facts and cleanup contracts.
    pub system: bool,
    /// Loaded editable rule bytes, admitted and digested on the worker.
    pub project_rule_bytes: Vec<u8>,
    /// Discover current platform context on the worker for each revision; false avoids tool probes.
    pub include_platform_rules: bool,
    /// Optional private macOS cache directory. Other platforms scan fresh; no UI-thread I/O.
    pub cache_dir: Option<PathBuf>,
    /// Storage, traversal and Git bounds.
    pub limits: JunkSessionLimits,
}
impl JunkSessionRequest {
    /// Selects shipped project rules and bounded defaults without doing filesystem discovery.
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            system: false,
            project_rule_bytes: PROJECT_RULES_JSON.as_bytes().to_vec(),
            include_platform_rules: false,
            cache_dir: None,
            limits: JunkSessionLimits::default(),
        }
    }

    /// Requests platform roots on the worker; performs no filesystem or tool discovery here.
    pub fn system() -> Self {
        Self {
            system: true,
            include_platform_rules: true,
            ..Self::new(Vec::new())
        }
    }
}

/// Synchronous control/admission error; worker failures arrive as events.
#[derive(Debug, thiserror::Error)]
pub enum JunkSessionControlError {
    /// Inputs, paths or limits are invalid.
    #[error("invalid junk session request")]
    InvalidRequest,
    /// A bounded input, revision space or the four-worker process limit was exceeded.
    #[error("junk session resource limit exceeded")]
    ResourceLimit,
    /// Previous revision or its events are still pending; drain its terminal event first.
    #[error("junk session is busy")]
    Busy,
    /// The session has been explicitly closed.
    #[error("junk session is closed")]
    Closed,
    /// Host could not create the worker thread.
    #[error("junk session worker unavailable: {0}")]
    WorkerUnavailable(#[from] std::io::Error),
}

/// One background worker with a bounded mailbox. Four workers maximum may coexist per process.
/// Drop cancels and closes without blocking on an OS call or joining on the UI thread.
pub struct JunkSession {
    shared: Arc<Shared>,
}

impl JunkSession {
    /// Starts junk analysis; no traversal, rule parsing, system discovery or tool probe runs here.
    pub fn start(mut request: JunkSessionRequest) -> Result<Self, JunkSessionControlError> {
        if (request.roots.is_empty() && !request.system)
            || (request.system && (!request.roots.is_empty() || !request.include_platform_rules))
            || request.limits.max_events == 0
            || request.limits.max_event_bytes < 4096
            || request.limits.max_candidates == 0
            || request.limits.max_candidate_bytes == 0
        {
            return Err(JunkSessionControlError::InvalidRequest);
        }
        if request.roots.len() > MAX_ROOTS
            || request
                .cache_dir
                .as_ref()
                .is_some_and(|path| path.as_os_str().len() > 64 * 1024)
            || request.project_rule_bytes.capacity() > 32 * 1024
            || request
                .roots
                .iter()
                .any(|path| path.as_os_str().len() > 64 * 1024)
        {
            return Err(JunkSessionControlError::ResourceLimit);
        }
        if !request.system {
            request.roots = crate::normalize_scan_roots(&request.roots)
                .map_err(|_| JunkSessionControlError::InvalidRequest)?;
        }
        ACTIVE_SESSIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_SESSIONS).then_some(active + 1)
            })
            .map_err(|_| JunkSessionControlError::ResourceLimit)?;
        let permit = WorkerPermit(false);
        let shared = Arc::new(Shared::new(request.limits));
        let worker_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("sweepx-junk-session".into())
            .spawn(move || {
                let _exit = mailbox::WorkerExit(Arc::clone(&worker_shared), permit);
                let session_id = crate::fresh_operation_ids("junk-session", &request.roots)
                    .operation_id
                    .to_string();
                let mut worker = Worker {
                    request,
                    session_id,
                    current: BTreeMap::new(),
                    presentations: PresentationIndex::default(),
                    scan_roots: Vec::new(),
                };
                let mut job = Job {
                    revision: JunkSessionRevision(1),
                    selected: None,
                    cancel: worker_shared.cancel_token(),
                };
                loop {
                    let mut writer =
                        Writer::new(Arc::clone(&worker_shared), job.revision, job.cancel.clone());
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        worker.run(&job, &mut writer)
                    }));
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(failure)) if failure.code == "cancelled" => {
                            writer.finish(JunkSessionOutcome::Cancelled, false, 0);
                        }
                        Ok(Err(failure)) => {
                            writer.failure(failure);
                            writer.finish(JunkSessionOutcome::Failed, false, 0);
                        }
                        Err(_) => {
                            writer.failure(JunkSessionFailure::new(
                                "worker_panicked",
                                "junk worker panicked",
                            ));
                            writer.finish(JunkSessionOutcome::Failed, false, 0);
                        }
                    }
                    let Some(next) = worker_shared.next_job() else {
                        break;
                    };
                    job = next;
                }
            })?;
        Ok(Self { shared })
    }

    /// Nonblocking event consumption, suitable for a UI tick.
    pub fn try_next_event(&self) -> Option<JunkSessionEvent> {
        self.shared.pop()
    }

    /// Waits for one event for at most `timeout`, without doing scanner work on this thread.
    pub fn next_event_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Option<JunkSessionEvent>, JunkSessionControlError> {
        self.shared.receive(timeout)
    }

    /// Stops new native work. Drain reliable events through Completed, or close to discard them.
    pub fn cancel(&self) {
        self.shared.cancel_token().cancel();
    }

    /// Changes ordering only, for an already admitted directory or its admitted ancestor.
    pub fn set_visible_directory(
        &self,
        path: Option<PathBuf>,
    ) -> Result<(), JunkSessionControlError> {
        if path
            .as_ref()
            .is_some_and(|path| !path.is_absolute() || path.as_os_str().len() > 64 * 1024)
        {
            return Err(JunkSessionControlError::InvalidRequest);
        }
        let mut state = self.shared.lock();
        if state.closed {
            return Err(JunkSessionControlError::Closed);
        }
        state.preferred = path;
        Ok(())
    }

    /// Refreshes the entire scope, including historical previews without current bindings.
    /// Full system refresh rediscovers current roots and includes independent temporary objects.
    /// Fresh complete observation is required before unseen old keys can be removed.
    pub fn refresh_all(&self) -> Result<JunkSessionRevision, JunkSessionControlError> {
        self.shared.refresh(Vec::new())
    }

    /// Refreshes selected native subtrees, preserving their parent rule context.
    /// Unknown keys or changed native bindings fail asynchronously without erasing old rows.
    /// Only selected subtrees recurse; shallow native ancestors preserve marker/Git context.
    /// Ancestor rows become historical until refreshed. Partial scopes publish no whole-root cache.
    pub fn refresh_selected(
        &self,
        keys: &[JunkCandidateKey],
    ) -> Result<JunkSessionRevision, JunkSessionControlError> {
        if keys.is_empty() || keys.len() > MAX_SELECTION {
            return Err(JunkSessionControlError::InvalidRequest);
        }
        self.shared.refresh(
            keys.iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        )
    }

    /// Cancels and closes the mailbox. Unconsumed events are intentionally discarded on close.
    pub fn close(&self) {
        self.shared.close();
    }

    /// Bounded shutdown observation for non-UI callers; native OS calls may outlive the timeout.
    pub fn wait_for_worker_exit(&self, timeout: Duration) -> Result<bool, JunkSessionControlError> {
        self.shared.wait_exit(timeout)
    }
}
impl Drop for JunkSession {
    fn drop(&mut self) {
        self.close();
    }
}
struct WorkerPermit(bool);
impl WorkerPermit {
    fn release(&mut self) {
        if !self.0 {
            self.0 = true;
            ACTIVE_SESSIONS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.release();
    }
}

struct Job {
    revision: JunkSessionRevision,
    selected: Option<Vec<JunkCandidateKey>>,
    cancel: CancellationToken,
}
type Rows = BTreeMap<JunkCandidateKey, Arc<JunkSessionCandidate>>;
struct Worker {
    request: JunkSessionRequest,
    session_id: String,
    current: Rows,
    // Display-only native paths survive cancellation independently of current binding authority.
    // This separately bounded index covers every reliably published candidate state.
    presentations: PresentationIndex,
    // Last full discovery scope. Selected refresh preserves original native directory contexts;
    // full system refresh rediscovers roots rather than retaining stale environment answers.
    scan_roots: Vec<PathBuf>,
}

impl Worker {
    fn run(&mut self, job: &Job, writer: &mut Writer) -> Result<(), JunkSessionFailure> {
        let system = self.request.system;
        self.run_with_discovery(job, writer, move |cancel| {
            PlatformJunkSetup::discover_with_cancel(cancel).map(|setup| {
                let roots = if system {
                    default_platform_junk_roots(&setup)
                } else {
                    Vec::new()
                };
                (setup, roots)
            })
        })
    }

    fn run_with_discovery(
        &mut self,
        job: &Job,
        writer: &mut Writer,
        discover: impl FnOnce(CancellationToken) -> Result<(PlatformJunkSetup, Vec<PathBuf>), String>,
    ) -> Result<(), JunkSessionFailure> {
        writer.send(JunkSessionEventKind::Started {
            scope: match &job.selected {
                Some(keys) => JunkSessionScope::Selected(keys.clone().into()),
                None => JunkSessionScope::All,
            },
        })?;
        writer.phase(JunkSessionPhase::Rules)?;
        if job.cancel.is_cancelled() {
            writer.finish(JunkSessionOutcome::Cancelled, false, 0);
            return Ok(());
        }
        let service = JunkService::from_rule_bytes(&self.request.project_rule_bytes)
            .map_err(|error| JunkSessionFailure::new("rules_invalid", error.to_string()))?;
        let rules_digest: [u8; 32] = {
            let mut hash = Sha256::new();
            hash.update(service.rule_bytes_digest);
            hash.update([u8::from(self.request.include_platform_rules)]);
            if self.request.include_platform_rules {
                hash.update(super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes());
            }
            hash.finalize().into()
        };
        if !self.request.system {
            self.scan_roots = self.request.roots.clone();
        }
        #[cfg(target_os = "macos")]
        let mut cache = if let Some(directory) = self.request.cache_dir.clone() {
            writer.phase(JunkSessionPhase::Cache)?;
            // Capture before preview reads, validation and traversal. Racing changes belong to
            // the next cache generation even if this revision later publishes complete facts.
            let cursor = crate::current_event_id();
            let mut reader = super::cache::CacheReader::with_rule_bytes(
                &directory,
                &self.request.project_rule_bytes,
                super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
            );
            if job.revision.0 == 1 && !self.request.system {
                self.restore_history(&mut reader, &service, rules_digest, job, writer)?;
            }
            Some((directory, cursor, reader))
        } else {
            None
        };
        if job.cancel.is_cancelled() {
            writer.finish(JunkSessionOutcome::Cancelled, false, 0);
            return Ok(());
        }
        writer.phase(JunkSessionPhase::Discovery)?;
        let (platform, discovered_roots) = if self.request.include_platform_rules {
            discover(job.cancel.clone())
                .map_err(|error| JunkSessionFailure::new("discovery_failed", error))?
        } else {
            (PlatformJunkSetup::default(), Vec::new())
        };
        let mut partial = platform.evidence.discovery_incomplete();
        if partial {
            writer.failure(JunkSessionFailure::new(
                "discovery_incomplete",
                "current platform layout or tool discovery is incomplete",
            ));
        }
        if job.cancel.is_cancelled() {
            writer.finish(JunkSessionOutcome::Cancelled, false, 0);
            return Ok(());
        }
        if self.request.system && job.selected.is_none() {
            self.scan_roots = normalize_discovered_roots(discovered_roots)?;
            #[cfg(not(target_os = "linux"))]
            if self.scan_roots.is_empty() {
                return Err(JunkSessionFailure::new(
                    "roots_unavailable",
                    "no supported platform junk root is available",
                ));
            }
        }
        #[cfg(target_os = "macos")]
        if self.request.system
            && job.revision.0 == 1
            && let Some((_, _, reader)) = &mut cache
        {
            writer.phase(JunkSessionPhase::Cache)?;
            self.restore_history(reader, &service, rules_digest, job, writer)?;
        }
        let selected = job
            .selected
            .as_ref()
            .map(|keys| {
                keys.iter()
                    .map(|key| {
                        self.current.get(key).cloned().ok_or_else(|| {
                            JunkSessionFailure::new(
                                "unknown_candidate",
                                "refresh key is not current in this session",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let paths = selected
            .as_ref()
            .map(|rows| {
                rows.iter()
                    .map(|row| {
                        native_path(row.candidate.source_entry.as_ref().ok_or_else(|| {
                            JunkSessionFailure::new(
                                "refresh_binding_unavailable",
                                "candidate has no directory locator",
                            )
                        })?)
                        .ok_or_else(|| {
                            JunkSessionFailure::new(
                                "refresh_binding_unavailable",
                                "candidate path cannot be reconstructed",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let roots = if let Some(rows) = &selected {
            for (key, row) in &self.current {
                if row.observed_native_path().is_some_and(|parent| {
                    paths.as_ref().is_some_and(|paths| {
                        paths
                            .iter()
                            .any(|path| path != &parent && path.starts_with(&parent))
                    })
                }) {
                    writer.send(JunkSessionEventKind::Invalidated { key: *key })?;
                }
            }
            validate_selected(rows, &job.cancel, self.request.limits.scan)?;
            let roots = rows
                .iter()
                .map(|row| {
                    native_root_path(
                        row.candidate
                            .source_entry
                            .as_ref()
                            .expect("selected source validated"),
                    )
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    JunkSessionFailure::new("refresh_binding_unavailable", "root path unavailable")
                })?;
            crate::normalize_scan_roots(&roots).map_err(|error| {
                JunkSessionFailure::new("refresh_binding_unavailable", error.to_string())
            })?
        } else {
            self.scan_roots.clone()
        };
        let roots = roots
            .into_iter()
            .map(ScanRoot::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| JunkSessionFailure::new("root_invalid", error.to_string()))?;
        #[cfg(target_os = "macos")]
        if cache.is_some() {
            writer.phase(JunkSessionPhase::Cache)?;
        }
        #[cfg(target_os = "macos")]
        let mut cache = cache.map(|(directory, cursor, reader)| {
            let paths: Vec<_> = roots.iter().map(|root| root.path().to_path_buf()).collect();
            let provider = if job.selected.is_some() {
                super::cache::provider::SubtreeCacheProvider::prepare_fragments(
                    &directory,
                    &paths,
                    &self.scan_roots,
                    reader,
                )
            } else {
                super::cache::provider::SubtreeCacheProvider::prepare_files(
                    &directory, &paths, reader,
                )
            };
            (directory, cursor, provider)
        });
        #[cfg(target_os = "macos")]
        let reuse = cache
            .as_ref()
            .map(|(_, _, provider)| provider as &dyn crate::SubtreeReuse);
        #[cfg(not(target_os = "macos"))]
        let reuse = None;
        writer.phase(JunkSessionPhase::Traversal)?;
        let mut pending = Rows::new();
        let old_bytes = self
            .current
            .values()
            .fold(0usize, |sum, row| sum.saturating_add(row.cost()));
        let mut observer = Observer {
            service: &service,
            platform: &platform,
            writer,
            pending: &mut pending,
            presentations: &mut self.presentations,
            paths: paths.as_deref(),
            limits: self.request.limits,
            retained_bytes: old_bytes,
            retained_rows: self.current.len(),
            rules_digest,
            observed: 0,
        };
        let scanner = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: ScanId::new(format!("{}:{}", self.session_id, job.revision.0)),
                resource_limits: self.request.limits.scan,
                ..ScannerOptions::default()
            },
        );
        let classifier = service.with_platform(&platform.rules, &platform.evidence);
        let scanned = if let Some(paths) = &paths {
            scanner.scan_classified_subtrees_with_observer(
                &roots,
                &job.cancel,
                &classifier,
                reuse,
                paths,
                &mut observer,
            )
        } else {
            scanner.scan_classified_with_observer(
                &roots,
                &job.cancel,
                &classifier,
                reuse,
                &mut observer,
            )
        }
        .map_err(|error| JunkSessionFailure::new("scan_failed", error.to_string()))?;
        partial |= !scanned.summary.boundaries.iter().all(|boundary| {
            matches!(
                boundary.kind,
                sweepx_platform::BoundaryKind::Symlink | sweepx_platform::BoundaryKind::RootSymlink
            )
        }) || scanned.subtree_coverage_complete.map_or_else(
            || {
                scanned
                    .coverages
                    .values()
                    .any(|coverage| !coverage.complete || coverage.details_lost)
            },
            |complete| !complete,
        );
        // A retained boundary/coverage log may be empty precisely because its budget was lost.
        // The observer sees failures before those caps and remains the conservative oracle.
        partial |= writer.coverage_incomplete;
        if let Some(failure) = writer.fault.take() {
            return Err(failure);
        }
        if job.cancel.is_cancelled() {
            writer.finish(JunkSessionOutcome::Cancelled, false, pending.len());
            return Ok(());
        }
        if let Some(rows) = &selected {
            validate_selected(rows, &job.cancel, self.request.limits.scan)?;
        }
        writer.phase(JunkSessionPhase::Formats)?;
        let mut formats = super::format::ProjectFormatSession::new(
            self.request.limits.formats,
            job.cancel.clone(),
        );
        for row in pending.values_mut() {
            formats.refresh(&mut Arc::make_mut(row).candidate);
            if job.cancel.is_cancelled() {
                writer.finish(JunkSessionOutcome::Cancelled, false, pending.len());
                return Ok(());
            }
        }
        writer.phase(JunkSessionPhase::Git)?;
        let mut git = GitEvidenceSession::new(self.request.limits.git, job.cancel.clone());
        git.capture_scan_facts(
            &scanned.summary,
            &scanned.coverages,
            &scanned.directory_markers,
            pending
                .values_mut()
                .map(|row| &mut Arc::make_mut(row).candidate),
        );
        let mut retained_bytes = old_bytes.saturating_add(
            pending
                .values()
                .fold(0usize, |sum, row| sum.saturating_add(row.cost())),
        );
        for (key, row) in &mut pending {
            let old_cost = row.cost();
            git.refresh(std::slice::from_mut(&mut Arc::make_mut(row).candidate));
            retained_bytes = retained_bytes
                .saturating_sub(old_cost)
                .saturating_add(row.cost());
            if retained_bytes > self.request.limits.max_candidate_bytes {
                return Err(JunkSessionFailure::new(
                    "resource_limit",
                    "current Git interpretation exceeds candidate retention budget",
                ));
            }
            if job.cancel.is_cancelled() {
                writer.finish(JunkSessionOutcome::Cancelled, false, pending.len());
                return Ok(());
            }
            self.presentations.send_candidate(
                writer,
                self.request.limits,
                *key,
                JunkSessionCandidateState::Current,
                rules_digest,
                Arc::clone(row),
            )?;
            // A cancelled/partial scope may still deliver useful current rows. Retain those
            // bindings for later refresh, without treating unseen old rows as absent.
            self.current.insert(*key, Arc::clone(row));
        }
        #[cfg(target_os = "linux")]
        if self.request.system && job.selected.is_none() {
            partial |=
                self.observe_temporary_objects(&platform, &mut pending, rules_digest, job, writer)?;
        }
        if let Some(rows) = &selected {
            validate_selected(rows, &job.cancel, self.request.limits.scan)?;
        }
        if job.cancel.is_cancelled() {
            writer.finish(JunkSessionOutcome::Cancelled, false, pending.len());
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        if let Some((directory, cursor, provider)) = &mut cache {
            writer.phase(JunkSessionPhase::CacheWrite)?;
            self.store_cache(
                directory,
                *cursor,
                provider,
                &scanned,
                &pending,
                &service,
                &platform,
                job,
                partial || writer.error_count > 0,
                writer,
            )?;
        }
        if job.cancel.is_cancelled() {
            writer.finish(JunkSessionOutcome::Cancelled, false, pending.len());
            return Ok(());
        }
        // All observations are finished. From Replacement onward the reliable commit stream
        // wins a racing cancel; close may still deliberately abandon consumption.
        writer.phase(JunkSessionPhase::Replacement)?;
        partial |= writer.error_count > 0;
        if !partial {
            self.presentations.replace_complete(
                writer,
                paths.as_deref(),
                &pending,
                &mut self.current,
            )?;
        }
        let count = pending.len();
        self.current.extend(pending);
        writer.finish(
            if partial {
                JunkSessionOutcome::Partial
            } else {
                JunkSessionOutcome::Complete
            },
            !partial,
            count,
        );
        Ok(())
    }
}

struct Observer<'a> {
    service: &'a JunkService,
    platform: &'a PlatformJunkSetup,
    writer: &'a mut Writer,
    pending: &'a mut Rows,
    presentations: &'a mut PresentationIndex,
    paths: Option<&'a [PathBuf]>,
    limits: JunkSessionLimits,
    retained_bytes: usize,
    retained_rows: usize,
    rules_digest: [u8; 32],
    observed: u64,
}
impl ClassifiedScanObserver for Observer<'_> {
    fn on_progress(&mut self, _: &Path, event: &ProgressEvent) {
        if let ProgressEvent::EntryObserved { path, .. } = event {
            self.observed = self.observed.saturating_add(1);
            self.writer.coalesce(JunkSessionEventKind::Progress {
                observed_entries: self.observed,
                path: path.clone(),
            });
        } else if let ProgressEvent::Error { path, reason } = event {
            self.writer.failure(JunkSessionFailure::new(
                "scan_observation_failed",
                format!("{}: {reason:?}", path.display()),
            ));
        }
    }
    fn on_boundary(&mut self, boundary: &sweepx_platform::BoundaryRecord) {
        self.writer.coverage_incomplete |= !matches!(
            boundary.kind,
            sweepx_platform::BoundaryKind::Symlink | sweepx_platform::BoundaryKind::RootSymlink
        );
        if let Err(failure) = self
            .writer
            .send(JunkSessionEventKind::Boundary(Box::new(boundary.clone())))
        {
            self.writer.abort(failure);
        }
    }
    fn on_directory_progress(&mut self, path: &Path, aggregate: &DirectoryAggregate) {
        if self.paths.is_some_and(|paths| {
            !paths
                .iter()
                .any(|selected| path.starts_with(selected) || selected.starts_with(path))
        }) {
            return;
        }
        self.writer
            .coalesce(JunkSessionEventKind::DirectoryStatistics {
                path: path.to_path_buf(),
                aggregate: Box::new(aggregate.clone()),
            });
    }
    fn preferred_directory(&self) -> Option<PathBuf> {
        self.writer.shared.lock().preferred.clone()
    }
    fn on_candidate(&mut self, entry: &ScannedEntry, rule: &str, aggregate: &DirectoryAggregate) {
        if self.writer.fault.is_some() || self.writer.shared.lock().closed {
            return;
        }
        let Some(path) = native_path(entry) else {
            self.writer.abort(JunkSessionFailure::new(
                "native_binding_unavailable",
                "candidate native path unavailable",
            ));
            return;
        };
        if self
            .paths
            .is_some_and(|paths| !paths.iter().any(|selected| path.starts_with(selected)))
        {
            return;
        }
        let aggregates = BTreeMap::from([(aggregate.directory_identity.as_str(), aggregate)]);
        let Some(candidate) = self.service.interpret(
            rule,
            entry,
            &aggregates,
            &self.platform.rules,
            &self.platform.evidence,
        ) else {
            self.writer.abort(JunkSessionFailure::new(
                "interpretation_failed",
                "retained decision cannot be interpreted",
            ));
            return;
        };
        let Some(key) = candidate_key(&candidate, &path) else {
            self.writer.abort(JunkSessionFailure::new(
                "native_binding_unavailable",
                "candidate identity is unknown",
            ));
            return;
        };
        let row = Arc::new(JunkSessionCandidate {
            candidate,
            facts: JunkSessionFacts::Directory(Box::new(aggregate.clone())),
        });
        if self.retained_rows >= self.limits.max_candidates
            || self.retained_bytes.saturating_add(row.cost()) > self.limits.max_candidate_bytes
        {
            self.writer.abort(JunkSessionFailure::new(
                "resource_limit",
                "old and pending candidate retention exceeds session budget",
            ));
            return;
        }
        self.retained_rows += 1;
        self.retained_bytes = self.retained_bytes.saturating_add(row.cost());
        if let Err(failure) = self.presentations.send_candidate(
            self.writer,
            self.limits,
            key,
            JunkSessionCandidateState::Base,
            self.rules_digest,
            Arc::clone(&row),
        ) {
            self.writer.abort(failure);
            return;
        }
        self.pending.insert(key, row);
    }
}

fn normalize_discovered_roots(roots: Vec<PathBuf>) -> Result<Vec<PathBuf>, JunkSessionFailure> {
    // Count raw discovery rows before deduplication so duplicates cannot hide resource pressure.
    if roots.len() > MAX_ROOTS || roots.iter().any(|path| path.as_os_str().len() > 64 * 1024) {
        return Err(JunkSessionFailure::new(
            "resource_limit",
            "system root discovery exceeds session limits",
        ));
    }
    if roots.is_empty() {
        return Ok(roots);
    }
    crate::normalize_scan_roots(&roots)
        .map_err(|error| JunkSessionFailure::new("root_invalid", error.to_string()))
}

fn candidate_key(candidate: &JunkCandidate, path: &Path) -> Option<JunkCandidateKey> {
    let row = candidate.source_entry.as_ref()?;
    let id = row.validated_identity().ok()??;
    let IdentityEvidence::Known { value: object } = &id.platform_file_identity else {
        return None;
    };
    let IdentityEvidence::Known { value: filesystem } = &id.filesystem_object_domain_identity
    else {
        return None;
    };
    let IdentityEvidence::Known { value: mount } = &id.volume_or_mount_identity else {
        return None;
    };
    let mut hash = Sha256::new();
    hash.update(b"sweepx-junk-candidate-key/v1");
    for bytes in [
        path.as_os_str().as_encoded_bytes(),
        candidate.rule_id.as_bytes(),
    ] {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    for value in [
        object.device.0,
        object.inode.0,
        filesystem.device.0,
        mount.value.0,
    ] {
        hash.update(value.to_le_bytes());
    }
    Some(JunkCandidateKey(hash.finalize().into()))
}

fn validate_selected(
    rows: &[Arc<JunkSessionCandidate>],
    cancel: &CancellationToken,
    limits: ScanResourceLimits,
) -> Result<(), JunkSessionFailure> {
    for row in rows {
        row.revalidate_native_binding(cancel, limits)?;
    }
    Ok(())
}

fn validate_directory_binding(
    row: &JunkSessionCandidate,
    cancel: &CancellationToken,
    limits: ScanResourceLimits,
) -> Result<(), JunkSessionFailure> {
    let scanner = DetailRescanner::new(HostPlatformScanner::new(), limits);
    let source = row.candidate.source_entry.as_ref().ok_or_else(|| {
        JunkSessionFailure::new(
            "refresh_binding_unavailable",
            "source directory unavailable",
        )
    })?;
    let locator = source
        .executable_native_locator()
        .ok()
        .flatten()
        .ok_or_else(|| {
            JunkSessionFailure::new(
                "refresh_binding_unavailable",
                "executable directory locator unavailable",
            )
        })?;
    let identity = source
        .identity
        .as_ref()
        .expect("executable locator validated identity");
    let root = ScanObjectIdentity {
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
    scanner
        .revalidate_directory(
            DetailRescanRequest {
                source_scan_id: &source.scan_id,
                source_root_identity: &root,
                source_directory_identity: identity,
                directory_locator: locator,
                revision: sweepx_model::DecimalU128::new(1),
                max_rows: 0,
            },
            cancel,
        )
        .map_err(|error| {
            JunkSessionFailure::new(
                if error == sweepx_scanner::DetailRescanError::Cancelled {
                    "cancelled"
                } else {
                    "refresh_binding_changed"
                },
                error.to_string(),
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests;
