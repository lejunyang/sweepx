//! Candidate interpretation over captured scan facts; no terminal rendering or deletion.

use super::ProjectJunkRule as JunkRule;
use super::platform::{
    PlatformJunkEvidence, PlatformJunkRule, ToolRootActivity, classify_tool_root,
    superseded_format_generations, tool_reported_root_for,
};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use sweepx_model::{ByteValue, ReasonCode, ScanEntryId};

/// Report-only garbage candidate and its retained evidence.
#[derive(Debug, Clone)]
pub struct JunkCandidate {
    /// Presentation path; never filesystem execution authority.
    pub path: String,
    /// Native path retained only for in-process actions; never serialized as authority.
    #[cfg(target_os = "linux")]
    pub native_path: Option<PathBuf>,
    /// Stable identifier of the admitted rule.
    pub rule_id: String,
    /// Stable risk tier, independent of confidence.
    pub risk: String,
    /// Size evidence, with logical fallback explicitly distinguished.
    pub reclaimable: ByteValue,
    /// Explanation from the admitted rule.
    pub evidence: String,
    /// Review date of the rule's primary sources.
    pub source_reviewed_at: String,
    /// Primary sources supporting the rule.
    pub references: Vec<String>,
    /// Scan-scoped source identity.
    pub entry_id: ScanEntryId,
    /// Captured ancestor scan identities for overlap suppression.
    pub ancestor_ids: BTreeSet<ScanEntryId>,
    /// `live` or `stale` for a tool cache; `None` when activity is not a meaningful question.
    ///
    /// A marker only. A stale cache is not deleted, pre-selected, or ranked differently here;
    /// platform junk classification is report-only and this simply records which copy the tool is
    /// using, so the reader can tell an abandoned cache from the working one.
    pub activity: Option<String>,
    /// Superseded format generations found inside this root, in profile declaration order.
    ///
    /// Distinct from `activity`: a currently reported root can still contain older layouts.
    /// This marker does not prove that no process is using those layouts.
    pub stale_formats: Vec<String>,
    /// True when `reclaimable` carries apparent logical size because allocation is unavailable.
    ///
    /// Reported rather than hidden: the two quantities differ on compressed, sparse and
    /// multi-stream files, and a consumer that needs allocation must be able to tell that it did
    /// not get it. Windows never claims allocation by design, so on Windows this is normally true.
    pub size_is_logical: bool,
    /// Git evidence augments project-rule confidence but never grants mutation authority.
    pub git: Option<GitIgnoreEvidence>,
    /// Stable report classification; platform candidates predate Git enrichment and omit it.
    pub classification: Option<String>,
    /// Stable confidence label for the classification, independent of the risk tier.
    pub confidence: Option<String>,
    /// Conditions that prevent this report-only candidate from being promoted.
    pub blockers: Vec<String>,
    /// Current required content observation; never persisted as a filesystem fact. A recognized
    /// self-declared format still does not prove exclusive ownership or inactivity.
    pub project_format: Option<super::format::ProjectFormatEvidence>,
    /// Current parent-manifest declarations, never cached as ownership or activity evidence.
    pub project_context: Option<super::manifest::ProjectContextEvidence>,
    /// Current admitted rule constraint; cache restoration starts as NotChecked. This enum is
    /// never native execution authority and cannot be waived by confidence or Git ignore status.
    pub execution_policy: JunkExecutionPolicy,
    /// Traversal facts only; reused solely with validated filesystem coverage/history.
    pub git_scan_facts: Option<super::git::GitScanFacts>,
    /// The scanned source row, retained for the bulk Trash path's identity revalidation. Present
    /// for freshly scanned candidates and for candidates restored from cache; `None` for the Linux
    /// temporary-object candidates, which use a different cleanup flow.
    pub source_entry: Option<sweepx_model::ScannedEntry>,
}

/// Current rule interpretation required before any junk-candidate Trash attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JunkExecutionPolicy {
    /// Historical/cache facts have not been interpreted with current admitted rules.
    NotChecked,
    /// The matched project rule explicitly permits reporting only.
    ReportOnly,
    /// Project layout may be reported, but exclusive ownership and inactivity remain unverified.
    RequireProjectOwnershipAndActivity,
    /// Platform candidate continues through its existing current native and coverage guards;
    /// this label does not itself authorize a move or waive any platform-specific blocker.
    NativeRevalidationRequired,
    /// Browser offline/application state is diagnostic only in junk views. Removing user data
    /// requires a separate explicit origin/path selection; generic junk Trash must refuse it.
    RequireUserDataSelection,
}

impl From<sweepx_catalog::junk::ProjectExecutionPolicy> for JunkExecutionPolicy {
    fn from(policy: sweepx_catalog::junk::ProjectExecutionPolicy) -> Self {
        match policy {
            sweepx_catalog::junk::ProjectExecutionPolicy::ReportOnly => Self::ReportOnly,
            sweepx_catalog::junk::ProjectExecutionPolicy::RequireOwnershipAndActivity => {
                Self::RequireProjectOwnershipAndActivity
            }
        }
    }
}

/// Git interpretation associated with a project artifact; never mutation authority.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GitIgnoreEvidence {
    /// Stable Git evidence status.
    pub status: String,
    /// Repository scan identity, or `git-native:` observation key for an ancestor outside the
    /// scan root. Neither representation carries native execution authority.
    pub repository_entry_id: String,
    /// Machine identifier of the Git observation contract.
    pub check: String,
}

impl JunkCandidate {
    /// Current junk execution blockers include project ownership/activity and explicit user-data
    /// selection. Names, markers, size, risk or Git ignore cannot waive these requirements;
    /// historical facts also need current rule interpretation.
    pub fn project_execution_blocker(&self) -> Option<&'static str> {
        if self.execution_policy == JunkExecutionPolicy::NotChecked {
            return Some("rule_evidence_not_revalidated");
        }
        // Preserve the established content-profile reason across both locales and API consumers.
        if self.project_format.is_some() {
            return Some("project_ownership_not_verified");
        }
        match self.execution_policy {
            JunkExecutionPolicy::RequireUserDataSelection => {
                Some("user_data_requires_explicit_selection")
            }
            JunkExecutionPolicy::ReportOnly => Some("project_report_only"),
            JunkExecutionPolicy::RequireProjectOwnershipAndActivity => {
                Some("project_ownership_not_verified")
            }
            // Required manifest declarations cannot become platform execution evidence if a
            // caller changes the policy/display fields. Explicit report-only reasons remain
            // independent above; neither path can authorize Trash from project observations.
            JunkExecutionPolicy::NativeRevalidationRequired => self
                .project_context
                .as_ref()
                .map(|_| "project_ownership_not_verified"),
            JunkExecutionPolicy::NotChecked => unreachable!("handled historical interpretation"),
        }
    }

    fn restore_execution_blocker(&mut self) {
        self.blockers.retain(|blocker| {
            !matches!(
                blocker.as_str(),
                "project_report_only"
                    | "project_ownership_not_verified"
                    | "project_activity_not_verified"
                    | "rule_evidence_not_revalidated"
                    | "user_data_requires_explicit_selection"
            )
        });
        if let Some(blocker) = self.project_execution_blocker() {
            self.blockers.push(blocker.into());
        }
        if matches!(
            self.execution_policy,
            JunkExecutionPolicy::RequireProjectOwnershipAndActivity
                | JunkExecutionPolicy::ReportOnly
        ) {
            self.blockers.push("project_activity_not_verified".into());
        }
    }

    /// Restores base project interpretation without letting Git or cached fields promote missing
    /// content evidence. Only the bounded content stage sets the current format outcome.
    pub(crate) fn reset_project_format_interpretation(&mut self) {
        self.restore_execution_blocker();
        let Some(format) = &self.project_format else {
            return;
        };
        use super::format::ProjectFormatStatus;
        self.blockers.retain(|b| {
            !matches!(
                b.as_str(),
                "project_format_not_checked" | "project_format_invalid" | "project_format_unknown"
            )
        });
        self.classification = Some(
            if format.status == ProjectFormatStatus::Recognized {
                "recognized_generated_format"
            } else {
                "project_layout"
            }
            .into(),
        );
        self.confidence = Some(
            if format.status == ProjectFormatStatus::Recognized {
                "medium"
            } else {
                "low"
            }
            .into(),
        );
        let blocker = match format.status {
            ProjectFormatStatus::NotChecked => Some("project_format_not_checked"),
            ProjectFormatStatus::Invalid => Some("project_format_invalid"),
            ProjectFormatStatus::Unknown => Some("project_format_unknown"),
            ProjectFormatStatus::Recognized => None,
        };
        if let Some(blocker) = blocker {
            self.blockers.push(blocker.into());
        }
    }

    /// Conservative owned-data estimate for session retention, not allocator RSS or file size.
    pub fn estimated_retained_bytes(&self) -> usize {
        let strings = [
            &self.path,
            &self.rule_id,
            &self.risk,
            &self.evidence,
            &self.source_reviewed_at,
        ];
        let mut bytes = strings.iter().fold(
            std::mem::size_of::<Self>().saturating_add(512),
            |sum, value| sum.saturating_add(value.capacity()),
        );
        for values in [&self.references, &self.stale_formats, &self.blockers] {
            bytes = bytes.saturating_add(
                values
                    .capacity()
                    .saturating_mul(std::mem::size_of::<String>()),
            );
            for value in values {
                bytes = bytes.saturating_add(value.capacity());
            }
        }
        for value in [&self.activity, &self.classification, &self.confidence]
            .into_iter()
            .flatten()
        {
            bytes = bytes.saturating_add(value.capacity());
        }
        bytes = bytes.saturating_add(self.entry_id.as_str().len());
        for id in &self.ancestor_ids {
            bytes = bytes.saturating_add(128).saturating_add(id.as_str().len());
        }
        if let Some(git) = &self.git {
            bytes = bytes
                .saturating_add(git.status.capacity())
                .saturating_add(git.repository_entry_id.capacity())
                .saturating_add(git.check.capacity());
        }
        if let Some(entry) = &self.source_entry {
            bytes = bytes.saturating_add(entry.estimated_retained_bytes());
        }
        #[cfg(target_os = "linux")]
        if let Some(path) = &self.native_path {
            bytes = bytes.saturating_add(path.as_os_str().len());
        }
        bytes
    }
}

/// Assembles one project junk candidate for an entry the classifier already matched.
/// Missing or inconsistent native directory facts return `None`, never a guessed identity.
pub fn assemble_project_candidate(
    rule: &JunkRule,
    entry: &sweepx_model::ScannedEntry,
    aggregates: &BTreeMap<&str, &sweepx_model::DirectoryAggregate>,
) -> Option<JunkCandidate> {
    if entry.object_type != sweepx_model::ObjectType::Directory {
        return None;
    }
    let locator = entry.validated_native_locator().ok()??;
    let identity = entry.identity.as_ref()?;
    let size = junk_size_for(aggregates.get(identity.entry_id.as_str()).copied());
    let mut candidate = JunkCandidate {
        path: entry.display_path.clone(),
        #[cfg(target_os = "linux")]
        native_path: None,
        rule_id: rule.id.clone(),
        risk: rule.risk.clone(),
        reclaimable: size.value,
        evidence: rule.evidence.clone(),
        source_reviewed_at: rule.source_reviewed_at.clone(),
        references: rule.references.clone(),
        entry_id: identity.entry_id.clone(),
        ancestor_ids: locator
            .parent_reopen_recipe
            .iter()
            .map(|component| component.entry_id.clone())
            .collect(),
        // Layout does not prove exclusive ownership or inactivity. Current declarations and
        // future activity observations remain separate from the traversal facts assembled here.
        activity: None,
        stale_formats: Vec::new(),
        size_is_logical: size.is_logical_fallback,
        git: None,
        classification: Some("known_generated".to_string()),
        confidence: Some("medium".to_string()),
        blockers: Vec::new(),
        project_format: rule
            .content_format
            .map(super::format::ProjectFormatEvidence::not_checked),
        project_context: rule
            .context_profile
            .map(super::manifest::ProjectContextEvidence::not_checked),
        execution_policy: rule.execution_policy.into(),
        git_scan_facts: None,
        source_entry: Some(entry.clone()),
    };
    candidate.reset_project_format_interpretation();
    Some(candidate)
}

/// Assembles one platform junk candidate for an entry the classifier already matched.
///
/// This is the former body of `platform_junk_candidates` without the rule/entry loops: the
/// classification decision was made during the walk, but activity, size and evidence are
/// assembled here from the retained aggregate.
/// Missing or inconsistent native directory facts return `None`. The rule must be admitted;
/// the caller supplies the walk-time decision, while this function supplies report interpretation.
pub fn assemble_platform_candidate(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    aggregates: &BTreeMap<&str, &sweepx_model::DirectoryAggregate>,
    evidence: &PlatformJunkEvidence,
) -> Option<JunkCandidate> {
    if entry.object_type != sweepx_model::ObjectType::Directory {
        return None;
    }
    let locator = entry.validated_native_locator().ok()??;
    let identity = entry.identity.as_ref()?;
    let activity = classify_tool_root(rule, entry, evidence)
        .map(|classification| classification.code().to_string());
    let stale_formats = superseded_format_generations(rule, entry, evidence);
    // Same allocation-versus-logical problem as the project rules, with one extra source: the
    // entry's own estimate, kept ahead of the logical fallback as the scanner's own claim.
    let aggregate = aggregates.get(identity.entry_id.as_str()).copied();
    let size = if aggregate.is_some() {
        junk_size_for(aggregate)
    } else {
        JunkSize {
            value: entry.reclaimable_estimate.clone(),
            is_logical_fallback: false,
        }
    };
    Some(JunkCandidate {
        path: entry.display_path.clone(),
        #[cfg(target_os = "linux")]
        native_path: None,
        rule_id: rule.id.clone(),
        risk: rule.risk.clone(),
        reclaimable: size.value,
        evidence: rule.evidence.clone(),
        source_reviewed_at: rule.source_reviewed_at.clone(),
        references: rule.references.clone(),
        entry_id: identity.entry_id.clone(),
        ancestor_ids: locator
            .parent_reopen_recipe
            .iter()
            .map(|component| component.entry_id.clone())
            .collect(),
        activity,
        stale_formats,
        size_is_logical: size.is_logical_fallback,
        git: None,
        classification: None,
        confidence: None,
        blockers: if rule.root_kind == "macos_browser_state" {
            vec!["user_data_requires_explicit_selection".into()]
        } else {
            Vec::new()
        },
        project_format: None,
        project_context: None,
        execution_policy: platform_execution_policy(rule),
        git_scan_facts: None,
        source_entry: Some(entry.clone()),
    })
}

// Interpret the admitted rule's purpose, not its risk label or a cache-looking path.
fn platform_execution_policy(rule: &PlatformJunkRule) -> JunkExecutionPolicy {
    if rule.root_kind == "macos_browser_state"
        || rule.root_kind == "pnpm_reported_store"
        || rule.root_kind == "osdk_reported_data"
        || rule.item_inventory.is_some()
    {
        JunkExecutionPolicy::RequireUserDataSelection
    } else {
        JunkExecutionPolicy::NativeRevalidationRequired
    }
}

/// Rebuilds transient interpretation of cached filesystem/rule facts for this invocation.
///
/// Filesystem reuse cannot prove current tool configuration or Git state. Tool answers come from
/// the supplied snapshot; missing answers remain unknown. Git enrichment requires a separate
/// current observation, so old Git confidence is discarded and an explicit blocker is retained.
/// Unknown rule IDs decline rather than being silently interpreted by a different rule.
pub fn refresh_candidate_interpretation(
    mut candidate: JunkCandidate,
    project_rules: &[JunkRule],
    platform_rules: &[PlatformJunkRule],
    evidence: &PlatformJunkEvidence,
) -> Option<JunkCandidate> {
    let is_project = project_rules
        .iter()
        .any(|rule| rule.id == candidate.rule_id);
    let platform_rule = platform_rules
        .iter()
        .find(|rule| rule.id == candidate.rule_id);
    if !is_project && platform_rule.is_none() {
        return None;
    }
    if let Some(rule) = platform_rule
        && matches!(
            rule.match_kind.as_str(),
            "verified_browser_cache" | "verified_cache_root" | "verified_known_root"
        )
        && candidate
            .source_entry
            .as_ref()
            .is_none_or(|entry| !evidence.matches_layout_root(rule, entry))
    {
        // A valid filesystem cache does not establish the current discovery scope or layout.
        // Decline a row whose native object is absent from this invocation's snapshot. The
        // caller separately reports incomplete discovery, so omission cannot claim an empty scope.
        return None;
    }
    candidate.git = None;
    candidate.classification = is_project.then(|| "known_generated".to_string());
    candidate.confidence = is_project.then(|| "medium".to_string());
    candidate.activity = None;
    candidate.stale_formats.clear();
    candidate.blockers.clear();
    candidate.execution_policy = project_rules
        .iter()
        .find(|rule| rule.id == candidate.rule_id)
        .map(|rule| rule.execution_policy.into())
        .unwrap_or_else(|| {
            platform_rule
                .map(platform_execution_policy)
                .unwrap_or(JunkExecutionPolicy::NativeRevalidationRequired)
        });
    candidate.project_format = project_rules
        .iter()
        .find(|rule| rule.id == candidate.rule_id)
        .and_then(|rule| rule.content_format)
        .map(super::format::ProjectFormatEvidence::not_checked);
    candidate.project_context = project_rules
        .iter()
        .find(|rule| rule.id == candidate.rule_id)
        .and_then(|rule| rule.context_profile)
        .map(super::manifest::ProjectContextEvidence::not_checked);
    candidate.reset_project_format_interpretation();
    if let Some(rule) = platform_rule
        && tool_reported_root_for(&rule.root_kind).is_some()
    {
        let current = candidate
            .source_entry
            .as_ref()
            .and_then(|entry| classify_tool_root(rule, entry, evidence));
        if current.is_none() {
            candidate
                .blockers
                .push("tool_evidence_not_revalidated".into());
        }
        candidate.activity = Some(
            current
                .unwrap_or(ToolRootActivity::Unknown)
                .code()
                .to_string(),
        );
        candidate.stale_formats = candidate
            .source_entry
            .as_ref()
            .map(|entry| superseded_format_generations(rule, entry, evidence))
            .unwrap_or_default();
    }
    if is_project {
        candidate
            .blockers
            .push("git_evidence_not_revalidated".into());
    }
    Some(candidate)
}

/// The size to report for a junk candidate, and which quantity it actually is.
///
/// `potentially_reclaimable_bytes` is derived from filesystem allocation, and the Windows adapter
/// deliberately refuses to claim allocation: `FILE_STANDARD_INFO` describes only the unnamed `$DATA`
/// stream, so an exact figure would be a guess wherever alternate streams, sparse ranges or
/// compression are in play. That refusal is correct and is not worked around here.
///
/// The consequence was that on Windows *every* candidate reported an unknown size — measured
/// 2026-09-05, 30 of 30, including 1.8 GB of browser caches. A cleaning tool that cannot say how
/// large anything is has not answered the user's question.
///
/// So when allocation is unavailable, the apparent logical size is reported instead, since it is
/// known exactly and is the quantity a user means by "how big is this cache". The two are not
/// interchangeable, so the caller is told which one it received rather than being left to assume
/// allocation.
pub struct JunkSize {
    /// Reportable size and its evidence state.
    pub value: ByteValue,
    /// True when `value` is logical size standing in for unavailable allocation.
    pub is_logical_fallback: bool,
}

/// Picks the reportable size for one aggregate, preferring allocation and falling back to logical.
pub fn junk_size_for(aggregate: Option<&sweepx_model::DirectoryAggregate>) -> JunkSize {
    let Some(aggregate) = aggregate else {
        return JunkSize {
            value: ByteValue::NotChecked {
                reason: ReasonCode::ResourceLimit,
            },
            is_logical_fallback: false,
        };
    };
    // Only an exactly known allocation is preferred. A lower bound or unknown allocation carries
    // less information than an exactly known logical size, so it does not win by being the
    // nominally correct field.
    if matches!(
        aggregate.potentially_reclaimable_bytes,
        ByteValue::Known { .. }
    ) {
        return JunkSize {
            value: aggregate.potentially_reclaimable_bytes.clone(),
            is_logical_fallback: false,
        };
    }
    match &aggregate.apparent_logical_bytes {
        known @ ByteValue::Known { .. } => JunkSize {
            value: known.clone(),
            is_logical_fallback: true,
        },
        // Neither is exact: keep the allocation-derived evidence, because its reason code explains
        // why the size is missing. Substituting an equally inexact logical value would discard that
        // explanation without adding anything.
        _ => JunkSize {
            value: aggregate.potentially_reclaimable_bytes.clone(),
            is_logical_fallback: false,
        },
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    use crate::junk::{JunkService, platform::PlatformJunkEvidence};
    use crate::{CancellationToken, CoreContext, MemorySnapshotStore, ScanRequest};

    #[test]
    fn native_layout_and_git_ignore_do_not_satisfy_project_execution_requirements() {
        let owner = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = owner.path().canonicalize().unwrap();
        #[cfg(windows)]
        let root = owner.path().to_path_buf();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
        std::fs::write(root.join("package.json"), b"{}\n").unwrap();
        std::fs::write(
            root.join(".gitignore"),
            b"target/\ndist/\nnode_modules/\n__pycache__/\n",
        )
        .unwrap();
        for name in ["target", "dist", "node_modules", "__pycache__"] {
            std::fs::create_dir(root.join(name)).unwrap();
            std::fs::write(
                root.join(name).join("personal-data"),
                b"preserve this payload",
            )
            .unwrap();
        }
        let status = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .arg(&root)
            .status()
            .unwrap();
        assert!(status.success());
        let service = JunkService::built_in().unwrap();
        let context = CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let scan = crate::scan_junk_with_store::<MemorySnapshotStore>(
            &context,
            &ScanRequest {
                roots: vec![root.clone()],
                state_dir: None,
            },
            None,
            &service,
            None,
        )
        .unwrap();
        let aggregates = scan
            .scan
            .summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect::<BTreeMap<_, _>>();
        let mut rows = scan
            .scan
            .summary
            .entries
            .iter()
            .filter_map(|entry| {
                let id = &entry.identity.as_ref()?.entry_id;
                service.interpret(
                    scan.decisions.get(id)?,
                    entry,
                    &aggregates,
                    &[],
                    &PlatformJunkEvidence::default(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 4);
        let mut git =
            crate::junk::git::GitEvidenceSession::new(Default::default(), CancellationToken::new());
        git.capture_scan_facts(
            &scan.scan.summary,
            &scan.coverages,
            &scan.directory_markers,
            &mut rows,
        );
        git.refresh(&mut rows);
        for row in &rows {
            let name = match &row.source_entry.as_ref().unwrap().native_basename {
                sweepx_model::NativeName::UnixBytes(bytes) => {
                    String::from_utf8(bytes.clone()).unwrap()
                }
                sweepx_model::NativeName::WindowsUtf16(units) => String::from_utf16(units).unwrap(),
            };
            let probe = std::process::Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(["check-ignore", "--quiet", "--"])
                .arg(&name)
                .status()
                .unwrap();
            assert!(
                probe.success(),
                "ordinary Git is the independent ignore oracle"
            );
            assert_eq!(row.git.as_ref().unwrap().status, "ignored");
            assert_eq!(
                row.confidence.as_deref(),
                Some("high"),
                "Git confidence still describes ignore evidence, never disposability"
            );
            assert_eq!(
                row.project_execution_blocker(),
                Some(if name == "dist" {
                    "project_report_only"
                } else {
                    "project_ownership_not_verified"
                })
            );
            assert!(
                row.blockers
                    .iter()
                    .any(|blocker| blocker == "project_activity_not_verified")
            );
            assert_eq!(
                std::fs::read(root.join(name).join("personal-data")).unwrap(),
                b"preserve this payload"
            );
        }
        #[cfg(target_os = "macos")]
        for row in rows {
            let restored =
                crate::junk::cache::StoredJunkCandidate::from_candidate(&row).into_candidate();
            assert_eq!(restored.execution_policy, JunkExecutionPolicy::NotChecked);
            assert_eq!(
                restored.project_execution_blocker(),
                Some("rule_evidence_not_revalidated")
            );
            let mut changed_rules = service.project_rules().to_vec();
            let rule = changed_rules
                .iter_mut()
                .find(|rule| rule.id == row.rule_id)
                .unwrap();
            rule.execution_policy = sweepx_catalog::junk::ProjectExecutionPolicy::ReportOnly;
            let refreshed = refresh_candidate_interpretation(
                restored,
                &changed_rules,
                &[],
                &PlatformJunkEvidence::default(),
            )
            .unwrap();
            assert_eq!(refreshed.execution_policy, JunkExecutionPolicy::ReportOnly);
            assert_eq!(
                refreshed.project_execution_blocker(),
                Some("project_report_only")
            );
        }
    }
    #[test]
    fn managed_tool_roots_cannot_become_blanket_trash_authority() {
        let rules = sweepx_catalog::junk::platform::load_platform_junk_rules().unwrap();
        for mut rule in rules.into_iter().filter(|r| {
            matches!(
                r.root_kind.as_str(),
                "pnpm_reported_store" | "osdk_reported_data"
            )
        }) {
            assert_eq!(
                platform_execution_policy(&rule),
                JunkExecutionPolicy::RequireUserDataSelection
            );
            rule.item_inventory = None;
            rule.risk = "R1".into();
            assert_eq!(
                platform_execution_policy(&rule),
                JunkExecutionPolicy::RequireUserDataSelection,
                "editing presentation fields cannot promote a managed root"
            );
        }
    }
}
