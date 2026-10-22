//! Core session to terminal bridge. The UI thread only consumes or enqueues bounded operations.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use sweepx_core::CancellationToken;
use sweepx_core::junk::session::{
    JunkAutoRefreshPause, JunkCandidateKey, JunkSession, JunkSessionCandidate,
    JunkSessionCandidateState, JunkSessionEventKind, JunkSessionOutcome, JunkSessionPhase,
    JunkSessionRequest, JunkSessionScope,
};
use sweepx_i18n::Locale;
use sweepx_model::{ByteValue, HumanSizeUnit, ScanSort};
use sweepx_tui::junk::{
    JunkEvent, JunkInspection, JunkIssueKind, JunkOutcome, JunkProvider, JunkRow, run_junk_browser,
};
mod items;
#[cfg(target_os = "linux")]
mod quarantine;

/// Scan scope selected by the CLI before any worker starts.
pub(crate) enum ScanScope {
    /// Current platform cache discovery, optionally restricted to rule IDs.
    Regular(Vec<String>),
    /// A manual full-disk pass with platform and project rules.
    Deep,
    /// Explicit roots using project rules.
    Directories,
}

pub(crate) fn run(
    roots: Vec<PathBuf>,
    scope: ScanScope,
    locale: Locale,
    unit: HumanSizeUnit,
    sort: ScanSort,
    cache_state_root: Option<PathBuf>,
    quarantine_base: Option<PathBuf>,
) -> ExitCode {
    #[cfg(not(target_os = "linux"))]
    if quarantine_base.is_some() {
        eprintln!("--quarantine-dir is available only for Linux temporary objects");
        return ExitCode::from(2);
    }
    let (scan_mode, mut request) = match scope {
        ScanScope::Regular(rule_ids) => {
            let mut request = JunkSessionRequest::system();
            request.platform_rule_ids = rule_ids;
            ("regular", request)
        }
        ScanScope::Deep => ("deep", JunkSessionRequest::deep(roots)),
        ScanScope::Directories => ("custom", JunkSessionRequest::new(roots)),
    };
    if let Some(root) = cache_state_root {
        request.set_state_cache(root);
    }
    // An interactive cleanup result must remain available while the user reviews it. Cache
    // writes can otherwise immediately replace a finished scan with another busy revision.
    request.watch = false;
    request.track_changes = true;
    let candidate_byte_budget = request.limits.max_candidate_bytes;
    let session = match JunkSession::start(request) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(8);
        }
    };
    let mut provider = Provider::new(session);
    provider.scan_mode = scan_mode;
    provider.limits.bytes = candidate_byte_budget;
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
    fn opens_items(&self) -> bool {
        matches!(self.rule(), "tool.npm-npx" | "tool.pnpm-store")
    }
    fn grouping(&self, locale: Locale) -> Option<sweepx_tui::junk::JunkGrouping> {
        let group = sweepx_core::junk::organization::organize(&self.row.candidate);
        Some(sweepx_tui::junk::JunkGrouping {
            category: group.category.id().into(),
            category_label: group.category.label(locale).into(),
            owner: group.owner_key,
            owner_label: group.owner_label,
            named_application: group.named_application,
        })
    }
    fn entry_identity(&self) -> Option<&str> {
        Some(self.row.candidate.entry_id.as_str())
    }
    fn ancestor_identities(&self) -> Vec<&str> {
        self.row
            .candidate
            .ancestor_ids
            .iter()
            .map(|id| id.as_str())
            .collect()
    }
    fn evidence(&self) -> &str {
        &self.row.candidate.evidence
    }
    fn context(&self) -> String {
        let candidate = &self.row.candidate;
        format!(
            "risk={} · classification={} · confidence={} · activity={} · format={} · projectContext={} · blockers={}",
            candidate.risk,
            candidate.classification.as_deref().unwrap_or("not_checked"),
            candidate.confidence.as_deref().unwrap_or("not_checked"),
            candidate.activity.as_deref().unwrap_or("not_checked"),
            candidate
                .project_format
                .as_ref()
                .map(|e| format!("{}/{}", e.status.code(), e.reason))
                .unwrap_or_else(|| "not_required".into()),
            candidate
                .project_context
                .as_ref()
                .map(super::junk_project_context_label)
                .unwrap_or_else(|| {
                    // Restored history has not loaded the current rule's input requirements.
                    // An absent cached projection cannot claim that no context is required.
                    if candidate.execution_policy
                        == sweepx_core::junk::candidate::JunkExecutionPolicy::NotChecked
                    {
                        "not_checked".into()
                    } else {
                        "not_required".into()
                    }
                }),
            candidate.blockers.join(",")
        )
    }
    fn user_context(&self, locale: Locale) -> String {
        use sweepx_core::junk::candidate::JunkExecutionPolicy as Policy;
        let candidate = &self.row.candidate;
        let (zh, en) = if self.preview || !self.current {
            (
                "等待本次检查，完成后可查看和选择。",
                "Waiting for the current check before selection.",
            )
        } else if !self.row.complete() {
            (
                "部分内容未能读取，按 e 查看位置和原因。",
                "Some contents could not be read; press e for locations and reasons.",
            )
        } else if matches!(
            candidate.rule_id.as_str(),
            "tool.npm-npx" | "tool.pnpm-store"
        ) {
            (
                "按 Enter 查看包、版本和清理选项。",
                "Press Enter for packages, versions and cleanup options.",
            )
        } else if candidate.rule_id == "tool.npm-other-data" {
            (
                "npm 旧版或其他工具留下的数据。用途尚未确认，按 Enter 查看文件。",
                "Legacy npm or other tool data. Purpose is unconfirmed; press Enter to inspect files.",
            )
        } else if candidate.rule_id.starts_with("tool.")
            && candidate.execution_policy != Policy::NativeRevalidationRequired
        {
            (
                "暂时保留：部分内容的格式或用途尚未确认。按 Enter 查看文件。",
                "Retained: the format or purpose of some contents is unconfirmed. Press Enter to inspect files.",
            )
        } else {
            match candidate.execution_policy {
                Policy::NativeRevalidationRequired => (
                    "可选择清理；清理后应用可能重新下载或生成这些内容。",
                    "Can be selected for cleanup; the application may download or rebuild these contents.",
                ),
                Policy::NotChecked => ("尚未检查，请刷新。", "Not checked yet; refresh this item."),
                Policy::RequireUserDataSelection => (
                    "包含应用或用户数据，需单独查看和选择。",
                    "Contains application or user data requiring separate review and selection.",
                ),
                Policy::ReportOnly | Policy::RequireProjectOwnershipAndActivity => (
                    "暂时保留：尚未确认项目是否仍需要这些内容。按 Enter 查看文件。",
                    "Retained: the project may still need these contents. Press Enter to inspect files.",
                ),
            }
        };
        if locale == Locale::ZhCn { zh } else { en }.into()
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

impl Row {
    fn registry_cost(&self) -> usize {
        // In addition to the model's 512-byte allowance, reserve map/set nodes and copies of
        // the stable key in historical state and one reconciliation event. Poll drains that
        // bounded batch before another action or revision; shared Arc payloads are counted once.
        self.retained_bytes()
            .saturating_add(1536)
            .saturating_add(self.key.capacity().saturating_mul(6))
    }
}

#[derive(Clone, Copy)]
struct RetentionLimits {
    rows: usize,
    bytes: usize,
}
impl Default for RetentionLimits {
    fn default() -> Self {
        Self {
            rows: 16_384,
            bytes: 64 * 1024 * 1024,
        }
    }
}

struct Provider {
    locations: BTreeMap<String, PathBuf>,
    pending_item_refresh: Option<PathBuf>,
    scan_mode: &'static str,
    session: JunkSession,
    rows: BTreeMap<String, Arc<Row>>,
    historical: BTreeSet<String>,
    revision: u64,
    busy: bool,
    complete: bool,
    limits: RetentionLimits,
    // Kept across revisions: cancelled Base rows still occupy this private registry.
    retained: usize,
    rejected: bool,
    trash: Option<Receiver<(String, Result<(), String>)>>,
    auto_pause: Option<JunkAutoRefreshPause>,
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
pub(crate) struct MutationPermit;
impl Drop for MutationPermit {
    fn drop(&mut self) {
        MUTATION_WORKER_ACTIVE.store(false, Ordering::Release);
    }
}

/// Shares admission across junk, file views and quarantine. A blocked native worker owns the
/// permit until it actually returns; closing its UI cannot admit another mutation worker.
pub(crate) fn mutation_permit() -> Result<MutationPermit, String> {
    MUTATION_WORKER_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "a system mutation worker is still running".to_string())?;
    Ok(MutationPermit)
}

impl Provider {
    fn location_event(
        &mut self,
        revision: u64,
        path: PathBuf,
        status: &'static str,
        mut detail: String,
    ) -> Option<JunkEvent> {
        if path.as_os_str().len() > 4096 {
            return None;
        }
        let key = self
            .locations
            .iter()
            .find(|(_, value)| **value == path)
            .map(|(key, _)| key.clone())
            .or_else(|| {
                (self.locations.len() < 256).then(|| format!("location-{}", self.locations.len()))
            })?;
        let display = path.to_string_lossy().into_owned();
        if display.len() > 4096 {
            return None;
        }
        if detail.len() > 2048 {
            let mut end = 2048;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        self.locations.insert(key.clone(), path);
        Some(JunkEvent::Location {
            revision,
            key,
            path: display,
            status,
            detail,
        })
    }

    fn new(session: JunkSession) -> Self {
        Self {
            locations: BTreeMap::new(),
            pending_item_refresh: None,
            scan_mode: "custom",
            session,
            rows: BTreeMap::new(),
            historical: BTreeSet::new(),
            revision: 0,
            busy: true,
            complete: false,
            limits: RetentionLimits::default(),
            retained: 0,
            rejected: false,
            trash: None,
            auto_pause: None,
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
        self.trash.is_some() || self.pending_item_refresh.is_some()
    }

    fn remove_row(&mut self, key: &str) {
        if let Some(row) = self.rows.remove(key) {
            self.retained = self.retained.saturating_sub(row.registry_cost());
        }
        self.historical.remove(key);
    }

    fn mark_historical(&mut self, key: &str) {
        // Unknown/rejected keys cannot grow auxiliary state independently of admitted rows.
        if self.rows.contains_key(key) {
            self.historical.insert(key.into());
        }
    }

    fn admit(&mut self, row: Arc<Row>) -> Option<JunkEvent> {
        let old = self.rows.get(&row.key).map_or(0, |old| old.registry_cost());
        let retained = self
            .retained
            .saturating_sub(old)
            .saturating_add(row.registry_cost());
        if retained > self.limits.bytes
            || (!self.rows.contains_key(&row.key) && self.rows.len() >= self.limits.rows)
        {
            self.complete = false;
            self.mark_historical(&row.key);
            if self.scan_mode != "deep" {
                self.session.cancel();
            }
            if self.rejected {
                return None;
            }
            self.rejected = true;
            return Some(JunkEvent::Error {
                revision: self.revision,
                message: "junk view retention limit; results incomplete".into(),
            });
        }
        self.retained = retained;
        if row.current {
            self.historical.remove(&row.key);
        } else {
            self.historical.insert(row.key.clone());
        }
        self.rows.insert(row.key.clone(), Arc::clone(&row));
        Some(JunkEvent::Candidate {
            revision: row.revision,
            current: row.current,
            historical: row.preview,
            row,
        })
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
            self.remove_row(&key);
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

    /// Translates one already-bounded worker event; no native observation runs here.
    fn translate_event(&mut self, revision: u64, kind: JunkSessionEventKind) -> Option<JunkEvent> {
        match kind {
            JunkSessionEventKind::Started { scope } => {
                self.revision = revision;
                self.busy = true;
                self.complete = false;
                self.rejected = false;
                let keys = match scope {
                    JunkSessionScope::All => {
                        self.locations.clear();
                        None
                    }
                    JunkSessionScope::Directories(paths) => Some(
                        self.rows
                            .iter()
                            .filter(|(_, row)| {
                                row.row.directory_aggregate().is_some()
                                    && row.row.observed_native_path().is_some_and(|path| {
                                        paths.iter().any(|parent| path.starts_with(parent))
                                    })
                            })
                            .map(|(key, _)| key.clone())
                            .collect(),
                    ),
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
                        JunkSessionPhase::Supplementary => "supplementary",
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
            JunkSessionEventKind::Location { path, complete } => {
                return self.location_event(
                    revision,
                    path,
                    match complete {
                        None => "pending",
                        Some(true) => "checked",
                        Some(false) => "partial",
                    },
                    String::new(),
                );
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
                return self.admit(row);
            }
            JunkSessionEventKind::Removed { key } => {
                let key = key.to_string();
                self.remove_row(&key);
                return Some(JunkEvent::Removed { revision, key });
            }
            JunkSessionEventKind::Invalidated { key } => {
                let key = key.to_string();
                self.mark_historical(&key);
                return Some(JunkEvent::Invalidated { revision, key });
            }
            JunkSessionEventKind::Boundary(boundary) => {
                let message = format!("{}: {}", boundary.path.display(), boundary.detail);
                let issue = Some(
                    if matches!(
                        boundary.kind,
                        sweepx_platform::BoundaryKind::Symlink
                            | sweepx_platform::BoundaryKind::RootSymlink
                    ) {
                        JunkEvent::Notice { revision, message }
                    } else {
                        JunkEvent::Issue {
                            revision,
                            kind: match boundary.kind {
                                _ if boundary.detail == "special filesystem entry rejected" => {
                                    JunkIssueKind::SkippedEntry
                                }
                                sweepx_platform::BoundaryKind::AccessDenied => {
                                    JunkIssueKind::Permission
                                }
                                sweepx_platform::BoundaryKind::Mount
                                | sweepx_platform::BoundaryKind::OtherFilesystem => {
                                    JunkIssueKind::OtherVolume
                                }
                                sweepx_platform::BoundaryKind::ResourceLimit => {
                                    JunkIssueKind::Capacity
                                }
                                _ => JunkIssueKind::Unavailable,
                            },
                            detail: message,
                        }
                    },
                );
                let excluded = matches!(
                    boundary.kind,
                    sweepx_platform::BoundaryKind::Symlink
                        | sweepx_platform::BoundaryKind::RootSymlink
                        | sweepx_platform::BoundaryKind::Mount
                        | sweepx_platform::BoundaryKind::OtherFilesystem
                ) || boundary.detail == "special filesystem entry rejected";
                if let Some(location) = self.location_event(
                    revision,
                    boundary.path.clone(),
                    if excluded { "excluded" } else { "partial" },
                    boundary.detail.clone(),
                ) {
                    if let Some(issue) = issue {
                        self.pending.push_back(issue);
                    }
                    return Some(location);
                }
                return issue;
            }
            JunkSessionEventKind::ToolQueryWarning(error) => {
                return Some(JunkEvent::Issue {
                    revision,
                    kind: JunkIssueKind::ToolQuery,
                    detail: error.detail,
                });
            }
            JunkSessionEventKind::Error(error)
            | JunkSessionEventKind::CacheWarning(error)
            | JunkSessionEventKind::WatchWarning(error) => {
                return Some(JunkEvent::Issue {
                    revision,
                    kind: match error.code {
                        code if code.starts_with("cache_") => JunkIssueKind::Cache,
                        "npm_discovery_incomplete" => JunkIssueKind::NpmDiscovery,
                        "layout_discovery_incomplete" => JunkIssueKind::AppDiscovery,
                        "tool_query_failed" => JunkIssueKind::AppDiscovery,
                        "resource_limit" => JunkIssueKind::Capacity,
                        "watch_unavailable" => JunkIssueKind::Watch,
                        _ => JunkIssueKind::Unavailable,
                    },
                    detail: error.detail,
                });
            }
            JunkSessionEventKind::Completed {
                mut outcome,
                mut replaced,
                ..
            } => {
                if self.rejected {
                    // The worker may have completed before seeing our cooperative cancellation.
                    // A dropped bridge row still prevents a complete view or mutation authority.
                    if outcome != JunkSessionOutcome::Failed {
                        outcome = JunkSessionOutcome::Partial;
                    }
                    self.pending.push_back(JunkEvent::Error {
                        revision,
                        message: "Candidate retention limit reached; scan incomplete. Narrow the scan scope.".into(),
                    });
                    replaced = false;
                }
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
        None
    }

    fn poll_trash(&mut self) -> Option<JunkEvent> {
        match self.trash.as_ref()?.try_recv() {
            Ok((key, result)) => {
                if result.is_err() {
                    self.mark_historical(&key);
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
                self.auto_pause = None;
                None
            }
        }
    }
}

impl JunkProvider for Provider {
    fn grouped(&self) -> bool {
        true
    }
    fn scan_mode(&self) -> &'static str {
        self.scan_mode
    }
    fn candidate_byte_budget(&self) -> usize {
        self.limits.bytes
    }
    fn open_items(
        &mut self,
        key: &str,
        locale: Locale,
        unit: HumanSizeUnit,
    ) -> Result<Option<Box<dyn JunkProvider>>, String> {
        let row = self.rows.get(key).ok_or("unknown candidate")?;
        let kind = row.row.candidate.rule_id.as_str();
        if !matches!(kind, "tool.npm-npx" | "tool.pnpm-store") {
            return Ok(None);
        }
        if self.busy || self.mutation_busy() || !row.current || row.preview {
            return Err(if locale == Locale::ZhCn {
                "请等待本次扫描完成，再查看包和版本。"
            } else {
                "Wait for this scan to finish before opening packages."
            }
            .into());
        }
        let pause = self
            .session
            .suspend_auto_refresh()
            .map_err(|e| e.to_string())?;
        let path = row
            .row
            .observed_native_path()
            .ok_or("native location unavailable")?;
        let child = if kind == "tool.npm-npx" {
            items::npx(
                row.row.clone(),
                path.parent().ok_or("npx root unavailable")?.to_path_buf(),
                locale,
                pause.clone(),
            )?
        } else {
            let config = crate::managed_cache::Config {
                tool: "pnpm",
                root: path.clone(),
                cache: path,
                projects: Vec::new(),
                package: None,
                max_links: None,
                unobserved: false,
            };
            Box::new(crate::managed_cache_tui::provider(
                config,
                locale,
                unit,
                Some(row.row.clone()),
                Some(pause.clone()),
            )?) as Box<dyn JunkProvider>
        };
        Ok(Some(Box::new(items::Child {
            provider: child,
            _pause: pause,
        })))
    }
    fn retry_location(&mut self, key: &str) -> Result<(), String> {
        if self.mutation_busy() {
            return Err("cleanup is running".into());
        }
        let path = self
            .locations
            .get(key)
            .ok_or("location unavailable")?
            .clone();
        self.session
            .refresh_directories(&[path])
            .map_err(|e| e.to_string())?;
        self.busy = true;
        Ok(())
    }
    fn refresh_changed(&mut self) -> Result<(), String> {
        if self.mutation_busy() {
            return Err("cleanup is running".into());
        }
        self.session.refresh_changed().map_err(|e| e.to_string())?;
        self.busy = true;
        Ok(())
    }
    fn refresh_after_items(&mut self, key: &str) -> Result<(), String> {
        let row = self.rows.get(key).ok_or("unknown candidate")?;
        let path = row
            .row
            .observed_native_path()
            .ok_or("native location unavailable")?;
        let scope = if row.row.candidate.rule_id == "tool.npm-npx" {
            path.parent().ok_or("npx parent unavailable")?.to_path_buf()
        } else {
            path
        };
        // A cancelled child can still be exiting a native call. Its worker keeps the lease;
        // retry admission from poll rather than joining it or dropping the requested refresh.
        self.pending_item_refresh = Some(scope);
        self.busy = true;
        Ok(())
    }
    fn inspect(&mut self, key: &str) -> Result<JunkInspection, String> {
        if self.mutation_busy() {
            return Err("a cleanup operation is running".into());
        }
        let row = self.rows.get(key).ok_or("unknown candidate key")?;
        if row.preview || row.revision != self.revision || row.row.directory_aggregate().is_none() {
            return Err("refresh this item before opening its files".into());
        }
        let directory = row
            .row
            .candidate
            .source_entry
            .clone()
            .ok_or("native directory unavailable")?;
        // Atomically prevent a watcher revision racing the captured binding. Native notifications
        // keep accumulating while the detail worker independently revalidates the original chain.
        // During a scan the consumer stops draining events while inspecting. The bounded
        // mailbox prevents a later revision from overtaking it; no filesystem work joins the
        // UI thread. An idle session needs a lease against independently enabled listeners.
        let pause = if self.busy {
            None
        } else {
            Some(
                self.session
                    .suspend_auto_refresh()
                    .map_err(|e| e.to_string())?,
            )
        };
        let provider = super::tui_adapter::tui_directory_detail_rescan_provider(&directory);
        Ok(JunkInspection {
            directory,
            provider: Arc::new(InspectionProvider {
                inner: provider,
                _pause: pause,
            }),
        })
    }
    fn poll(&mut self) -> Option<JunkEvent> {
        if let Some(path) = &self.pending_item_refresh {
            match self.session.refresh_directories(std::slice::from_ref(path)) {
                Ok(_) => {
                    self.pending_item_refresh = None;
                }
                Err(sweepx_core::junk::session::JunkSessionControlError::Busy) => return None,
                Err(error) => {
                    self.pending_item_refresh = None;
                    self.busy = false;
                    self.pending.push_back(JunkEvent::Completed {
                        revision: self.revision,
                        outcome: JunkOutcome::Failed,
                        replaced: false,
                    });
                    return Some(JunkEvent::Error {
                        revision: self.revision,
                        message: error.to_string(),
                    });
                }
            }
        }

        if let Some(event) = self.pending.pop_front() {
            if self.pending.is_empty() {
                // The preceding batch may have removed every row whose estimate reserved this
                // storage. Do not carry its empty allocation into a later admitted revision.
                self.pending = VecDeque::new();
            }
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
            if let Some(event) = self.translate_event(revision, event.kind) {
                return Some(event);
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
        if self.busy || self.mutation_busy() || !self.pending.is_empty() {
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
                .any(|row| !row.current || row.preview || row.row.directory_aggregate().is_none())
        {
            // Historical previews and cancelled Base keys are only display observations.
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
        if self.busy || !self.complete || self.mutation_busy() || !self.pending.is_empty() {
            return Err("complete the scan or refresh first".into());
        }
        let rows = self.selected(keys)?;
        if rows
            .iter()
            .any(|row| row.row.candidate.project_execution_blocker().is_some())
        {
            return Err(
                "project rule is report-only or exclusive ownership/activity is unverified".into(),
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
        let pause = self
            .session
            .suspend_auto_refresh()
            .map_err(|error| error.to_string())?;
        let native_pause = pause.clone();
        let permit = mutation_permit()?;
        let (sender, receiver) = sync_channel(1);
        self.trash_cancel = CancellationToken::new();
        let cancel = self.trash_cancel.clone();
        std::thread::Builder::new()
            .name("sweepx-junk-trash".into())
            .spawn(move || {
                let _permit = permit;
                let _pause = native_pause;
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
        self.auto_pause = Some(pause);
        Ok(())
    }
    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.session.close();
            self.trash_cancel.cancel();
            self.trash = None;
            self.auto_pause = None;
            self.rows.clear();
            self.historical.clear();
            self.pending = VecDeque::new();
            self.retained = 0;
            #[cfg(target_os = "linux")]
            {
                self.quarantine = None;
                self.quarantine_keys.clear();
            }
        }
    }
    #[cfg(target_os = "linux")]
    fn preview_quarantine(&mut self, keys: &[String]) -> Result<u64, String> {
        if self.closed
            || self.busy
            || !self.complete
            || self.mutation_busy()
            || !self.pending.is_empty()
        {
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
        let pause = self
            .session
            .suspend_auto_refresh()
            .map_err(|error| error.to_string())?;
        let worker = quarantine::Worker::start(
            operation,
            rows,
            self.quarantine_base.clone(),
            self.complete,
            pause.clone(),
        )?;
        self.quarantine_operation = operation;
        self.quarantine_keys = keys.to_vec();
        self.quarantine = Some(worker);
        self.auto_pause = Some(pause);
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
                self.auto_pause = None;
            }
        }
    }
}

/// The lease survives a detached/non-cooperative detail worker; notifications are never discarded.
struct InspectionProvider {
    inner: super::tui_adapter::TuiDetailRescanProvider,
    _pause: Option<JunkAutoRefreshPause>,
}
impl sweepx_tui::DetailRescanProvider for InspectionProvider {
    fn prepare_detail_rescan(&self) {
        self.inner.prepare_detail_rescan();
    }
    fn rescan_detail(
        &self,
        request: &sweepx_tui::DetailRescanRequest,
    ) -> sweepx_tui::DetailRescanResult {
        self.inner.rescan_detail(request)
    }
    fn cancel_detail_rescan(&self) {
        self.inner.cancel_detail_rescan();
    }
    fn set_progress_sink(
        &self,
        sink: Option<std::sync::mpsc::SyncSender<sweepx_tui::DetailRescanProgress>>,
    ) {
        self.inner.set_progress_sink(sink);
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests;
