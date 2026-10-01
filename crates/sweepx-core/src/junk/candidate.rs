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
    /// The scanned source row, retained for the bulk Trash path's identity revalidation. Present
    /// for freshly scanned candidates and for candidates restored from cache; `None` for the Linux
    /// temporary-object candidates, which use a different cleanup flow.
    pub source_entry: Option<sweepx_model::ScannedEntry>,
}

/// Git interpretation associated with a project artifact; never mutation authority.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GitIgnoreEvidence {
    /// Stable Git evidence status.
    pub status: String,
    /// Repository scan identity, serialized without native execution authority.
    pub repository_entry_id: String,
    /// Machine identifier of the Git observation contract.
    pub check: String,
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
        // A project build output has no "which copy is the tool using" question: it belongs to
        // the tree it sits in. Claiming an activity here would be noise.
        activity: None,
        stale_formats: Vec::new(),
        size_is_logical: size.is_logical_fallback,
        git: None,
        classification: Some("known_generated".to_string()),
        confidence: Some("medium".to_string()),
        blockers: Vec::new(),
        source_entry: Some(entry.clone()),
    })
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
        blockers: Vec::new(),
        source_entry: Some(entry.clone()),
    })
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
    candidate.git = None;
    candidate.classification = is_project.then(|| "known_generated".to_string());
    candidate.confidence = is_project.then(|| "medium".to_string());
    candidate.activity = None;
    candidate.stale_formats.clear();
    candidate.blockers.clear();
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
