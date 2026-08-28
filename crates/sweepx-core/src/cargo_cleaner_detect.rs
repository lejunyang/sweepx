use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::json;
use sweepx_cleaner_schema::RiskTier;
use sweepx_cleaner_vm::{EvalState, EvaluationContext, RuleEvaluation, VmValue, evaluate_rule};
use sweepx_model::{
    ArithmeticState, ByteValue, Coverage, CoverageState, DecimalU128, DirectoryAggregate,
    EvidenceValue, FieldProvenance, NativeLocatorEvidence, NativeName, ObjectType, ScanEntryId,
    ScanObjectIdentity, ScannedEntry,
};
use sweepx_platform::{BoundaryKind, CancellationToken, PlatformScanner};
use sweepx_scanner::{LocatorReader, ScanSummary};

use crate::{
    CORE_VERSION, CoreError, LoadedBuiltInCleaner,
    cargo_cleaner_evidence::{
        CargoConfigScopeProjectionV1, CargoConfigScopeRuntime, CargoEvidenceStateProjection,
        CargoTypedEvidenceV1, collect_and_produce_cargo_typed_evidence,
    },
};

pub const CARGO_CLEANER_ID: &str = "org.sweepx.cargo-target";
const CARGO_RULE_ID: &str = "cargo-target-v1";
const CARGO_WORKSPACE_EVIDENCE_UNKNOWN: &str = "cargo_workspace_evidence_unknown";
const CARGO_CONFIG_EVIDENCE_UNKNOWN: &str = "cargo_config_target_dir_evidence_unknown";
const CARGO_TARGET_SHAPE_UNKNOWN: &str = "cargo_target_shape_unknown";
const TARGET_AGGREGATE_MISSING: &str = "target_aggregate_missing";
const TARGET_AGGREGATE_INVALID: &str = "target_aggregate_invalid";
const TARGET_AGGREGATE_INCOMPLETE: &str = "target_aggregate_incomplete";
const TARGET_RECLAIMABLE_UNKNOWN: &str = "target_reclaimable_unknown";
const SOURCE_SCAN_BOUNDARIES_PRESENT: &str = "source_scan_boundaries_present";
const SOURCE_SCAN_INCOMPLETE: &str = "source_scan_incomplete";
const SOURCE_SCAN_WARNING: &str = "source_scan_warning";
const CARGO_REQUIRED_EVIDENCE_UNKNOWN: &str = "cargo_required_evidence_unknown";
const CARGO_RULE_MATCH_REPORT_ONLY: &str = "cargo_rule_match_report_only";
const NO_CARGO_TARGET_HINT: &str = "no_cargo_target_hint";
const CARGO_LAYOUT_LIMIT: usize = 16;
const CARGO_LAYOUT_LIMIT_REACHED: &str = "cargo_layout_limit_reached";
pub const BUILTIN_MANIFEST_INCOMPATIBLE: &str = "builtin_manifest_incompatible";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentalCargoDetectDisposition {
    ReportOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentalEvidenceState {
    Known,
    Unknown,
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoIdentityEvidence {
    pub scan_id: String,
    pub root_entry_id: String,
    pub manifest_entry_id: String,
    pub target_entry_id: String,
    pub target_parent_entry_id: String,
    pub native_locator_validated: bool,
    pub root_parent_lineage_bound: bool,
    pub same_filesystem_domain: bool,
    pub same_volume_or_mount: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoRequiredEvidence {
    pub workspace: ExperimentalEvidenceState,
    pub configured_target_dir: ExperimentalEvidenceState,
    pub target_shape: ExperimentalEvidenceState,
    pub final_complete_aggregate: ExperimentalEvidenceState,
    pub no_boundary: ExperimentalEvidenceState,
    pub not_shared: ExperimentalEvidenceState,
    pub activity: ExperimentalEvidenceState,
}

impl ExperimentalCargoRequiredEvidence {
    fn supports_rule_match(&self) -> bool {
        self.workspace == ExperimentalEvidenceState::Known
            && self.configured_target_dir == ExperimentalEvidenceState::Known
            && self.target_shape == ExperimentalEvidenceState::Known
            && self.final_complete_aggregate == ExperimentalEvidenceState::Known
            && self.no_boundary == ExperimentalEvidenceState::Known
            && self.not_shared == ExperimentalEvidenceState::Known
            && self.activity == ExperimentalEvidenceState::Known
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoWorkspaceEvidence {
    pub state: ExperimentalEvidenceState,
    pub reason_code: Option<String>,
    pub workspace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoTargetDirEvidence {
    pub state: ExperimentalEvidenceState,
    pub reason_code: Option<String>,
    pub relative_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoTargetShapeEvidence {
    pub state: ExperimentalEvidenceState,
    pub reason_code: Option<String>,
    pub classification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoStateEvidence {
    pub state: ExperimentalEvidenceState,
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoTypedEvidence {
    pub workspace: ExperimentalCargoWorkspaceEvidence,
    pub config_scope: CargoConfigScopeProjectionV1,
    pub target_dir: ExperimentalCargoTargetDirEvidence,
    pub target_shape: ExperimentalCargoTargetShapeEvidence,
    pub not_shared: ExperimentalCargoStateEvidence,
    pub activity: ExperimentalCargoStateEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoAggregateEvidence {
    pub state: ExperimentalEvidenceState,
    pub revision: Option<DecimalU128>,
    pub coverage: Option<Coverage>,
    pub arithmetic_state: Option<ArithmeticState>,
    pub potentially_reclaimable_bytes: Option<ByteValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoRuleEvaluation {
    pub fact_state: String,
    pub inference_state: String,
    /// This is the rule VM's provisional floor, not a finalized Candidate risk.
    pub provisional_risk: String,
    pub report_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoReadOnlyEvidence {
    pub identity: ExperimentalCargoIdentityEvidence,
    pub cargo: ExperimentalCargoTypedEvidence,
    pub required: ExperimentalCargoRequiredEvidence,
    pub aggregate: ExperimentalCargoAggregateEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoRuleObservation {
    pub observation_id: String,
    pub cleaner_id: String,
    pub cleaner_version: String,
    pub rule_id: String,
    pub display_path: String,
    pub observed_root: String,
    pub disposition: ExperimentalCargoDetectDisposition,
    pub reason_codes: Vec<String>,
    pub executable: bool,
    pub rule_evaluation: ExperimentalCargoRuleEvaluation,
    pub evidence: ExperimentalCargoReadOnlyEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoScanEvidence {
    pub incomplete: bool,
    pub warning_count: DecimalU128,
    pub error_count: DecimalU128,
    pub boundary_count: DecimalU128,
    pub partial_boundary_count: DecimalU128,
    pub incomplete_aggregate_count: DecimalU128,
}

#[derive(Debug, Clone)]
pub struct ExperimentalCargoDetectResult {
    pub matches: Vec<ExperimentalCargoRuleObservation>,
    pub hints: Vec<ExperimentalCargoRuleObservation>,
    pub reasons: Vec<String>,
    pub scan: ExperimentalCargoScanEvidence,
}

impl ExperimentalCargoDetectResult {
    pub fn collection_cancelled(&self) -> bool {
        self.matches
            .iter()
            .chain(self.hints.iter())
            .any(|observation| {
                observation.evidence.cargo.workspace.reason_code.as_deref() == Some("cancelled")
                    || observation.evidence.cargo.target_dir.reason_code.as_deref()
                        == Some("cancelled")
                    || observation
                        .evidence
                        .cargo
                        .target_shape
                        .reason_code
                        .as_deref()
                        == Some("cancelled")
            })
    }

    pub fn requires_partial_status(&self) -> bool {
        self.scan.incomplete || !self.hints.is_empty()
    }

    pub fn primary_reason_code(&self) -> &'static str {
        if self.collection_cancelled() {
            "cancelled"
        } else if self.scan.incomplete {
            SOURCE_SCAN_INCOMPLETE
        } else if !self.hints.is_empty() {
            CARGO_REQUIRED_EVIDENCE_UNKNOWN
        } else if !self.matches.is_empty() {
            CARGO_RULE_MATCH_REPORT_ONLY
        } else {
            NO_CARGO_TARGET_HINT
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExperimentalCargoTerminalDisposition {
    Complete,
    Partial,
    Cancelled,
}

impl ExperimentalCargoDetectResult {
    pub fn terminal_disposition(&self) -> ExperimentalCargoTerminalDisposition {
        if self.collection_cancelled() {
            ExperimentalCargoTerminalDisposition::Cancelled
        } else if self.requires_partial_status() {
            ExperimentalCargoTerminalDisposition::Partial
        } else {
            ExperimentalCargoTerminalDisposition::Complete
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BoundEntry<'a> {
    entry: &'a ScannedEntry,
    identity: &'a ScanObjectIdentity,
    locator: &'a NativeLocatorEvidence,
}

#[derive(Debug, Clone, Copy)]
struct BoundCargoLayoutHint<'a> {
    root: BoundEntry<'a>,
    manifest: BoundEntry<'a>,
    target: BoundEntry<'a>,
}

#[derive(Debug, Clone, Copy)]
enum AggregateLookup<'a> {
    Valid(&'a DirectoryAggregate),
    Missing,
    Invalid,
}

pub fn cargo_cleaner(
    cleaners: &[LoadedBuiltInCleaner],
) -> Result<&LoadedBuiltInCleaner, CoreError> {
    cleaners
        .iter()
        .find(|cleaner| cleaner.package.manifest.id == CARGO_CLEANER_ID)
        .ok_or_else(|| CoreError::InvalidCleanerRef(CARGO_CLEANER_ID.to_string()))
}

pub fn detect_live_cargo_cleaner_candidates(
    summary: &ScanSummary,
    cleaner: &LoadedBuiltInCleaner,
    source_scan_incomplete: bool,
    source_scan_warning_count: usize,
    reader: &LocatorReader<impl PlatformScanner>,
    config_scope_runtime: CargoConfigScopeRuntime,
    cancel: &CancellationToken,
) -> Result<ExperimentalCargoDetectResult, CoreError> {
    detect_live_cargo_cleaner_candidates_with_collector(
        summary,
        cleaner,
        source_scan_incomplete,
        source_scan_warning_count,
        |layout| {
            project_collected_cargo_typed_evidence(&collect_and_produce_cargo_typed_evidence(
                reader,
                summary,
                &layout.root.identity.entry_id,
                &layout.manifest.identity.entry_id,
                &layout.target.identity.entry_id,
                config_scope_runtime,
                cancel,
            ))
        },
    )
}

fn detect_live_cargo_cleaner_candidates_with_collector<F>(
    summary: &ScanSummary,
    cleaner: &LoadedBuiltInCleaner,
    source_scan_incomplete: bool,
    source_scan_warning_count: usize,
    collect_typed_evidence: F,
) -> Result<ExperimentalCargoDetectResult, CoreError>
where
    F: Fn(&BoundCargoLayoutHint<'_>) -> ExperimentalCargoTypedEvidence,
{
    if cleaner.package.manifest.id != CARGO_CLEANER_ID {
        return Err(CoreError::InvalidCleanerRef(
            cleaner.package.manifest.id.clone(),
        ));
    }
    if !cleaner.compatible {
        return Err(CoreError::CleanerCompat {
            cleaner_ref: format!(
                "{}@{}",
                cleaner.package.manifest.id, cleaner.package.manifest.version
            ),
            required_core: cleaner.package.manifest.requires.core.clone(),
            current_core: CORE_VERSION.to_string(),
        });
    }
    let rule = cleaner
        .package
        .rules
        .iter()
        .find_map(|(_, rule)| (rule.id == CARGO_RULE_ID).then_some(rule))
        .ok_or_else(|| {
            CoreError::InvalidCleanerRef(format!("{CARGO_CLEANER_ID}@{CARGO_RULE_ID}"))
        })?;

    let mut matches = Vec::new();
    let mut hints = Vec::new();
    let mut scan_evidence =
        scan_evidence(summary, source_scan_incomplete, source_scan_warning_count);
    let layouts = bound_cargo_layout_hints(summary);
    let layouts_truncated = layouts.len() > CARGO_LAYOUT_LIMIT;
    if layouts_truncated {
        scan_evidence.incomplete = true;
    }
    for layout in layouts.into_iter().take(CARGO_LAYOUT_LIMIT) {
        let cargo = collect_typed_evidence(&layout);
        let aggregate_lookup = target_aggregate(summary, &layout.target);
        let aggregate = match aggregate_lookup {
            AggregateLookup::Valid(aggregate) => Some(aggregate),
            AggregateLookup::Missing | AggregateLookup::Invalid => None,
        };
        let required = required_evidence(summary, aggregate, &cargo);
        let evaluation = evaluate_rule(rule, &build_rule_context(&layout, aggregate, &cargo))?;
        let mut reason_codes = observation_reason_codes(
            &evaluation,
            &aggregate_lookup,
            aggregate,
            &scan_evidence,
            &cargo,
        );
        reason_codes.sort();
        reason_codes.dedup();
        let observation = ExperimentalCargoRuleObservation {
            observation_id: format!(
                "cargo-target-observation:{}",
                layout.target.identity.entry_id
            ),
            cleaner_id: cleaner.package.manifest.id.clone(),
            cleaner_version: cleaner.package.manifest.version.clone(),
            rule_id: rule.id.clone(),
            display_path: layout.target.entry.display_path.clone(),
            observed_root: layout.root.entry.display_path.clone(),
            disposition: ExperimentalCargoDetectDisposition::ReportOnly,
            reason_codes,
            executable: false,
            rule_evaluation: ExperimentalCargoRuleEvaluation {
                fact_state: eval_state_label(evaluation.fact_state.clone()).to_string(),
                inference_state: eval_state_label(evaluation.inference_state.clone()).to_string(),
                provisional_risk: risk_label(evaluation.resolved_risk).to_string(),
                report_only: evaluation.report_only,
            },
            evidence: ExperimentalCargoReadOnlyEvidence {
                identity: identity_evidence(&layout),
                cargo,
                aggregate: aggregate_evidence(&aggregate_lookup),
                required: required.clone(),
            },
        };
        if rule_is_a_match(&evaluation, &required, &scan_evidence) {
            matches.push(observation);
        } else {
            hints.push(observation);
        }
    }

    let mut reasons = BTreeSet::new();
    for observation in matches.iter().chain(hints.iter()) {
        reasons.extend(observation.reason_codes.iter().cloned());
    }
    if scan_evidence.incomplete {
        reasons.insert(SOURCE_SCAN_INCOMPLETE.to_string());
    }
    if source_scan_warning_count > 0 {
        reasons.insert(SOURCE_SCAN_WARNING.to_string());
    }
    if layouts_truncated {
        reasons.insert(CARGO_LAYOUT_LIMIT_REACHED.to_string());
    }
    Ok(ExperimentalCargoDetectResult {
        matches,
        hints,
        reasons: reasons.into_iter().collect(),
        scan: scan_evidence,
    })
}

fn bound_entry(entry: &ScannedEntry) -> Option<BoundEntry<'_>> {
    if !matches!(entry.provenance, FieldProvenance::LiveObservation { .. })
        || !matches!(
            entry.coverage.provenance,
            FieldProvenance::LiveObservation { .. }
        )
    {
        return None;
    }
    let identity = entry.validated_identity().ok().flatten()?;
    let locator = entry.executable_native_locator().ok().flatten()?;
    Some(BoundEntry {
        entry,
        identity,
        locator,
    })
}

fn bound_root(entry: &ScannedEntry) -> Option<BoundEntry<'_>> {
    let root = bound_entry(entry)?;
    (root.entry.object_type == ObjectType::Directory
        && root.identity.parent_id.is_none()
        && root.identity.entry_id == root.identity.scan_root_id
        && root.locator.parent_reopen_recipe.is_empty()
        && root.locator.entry == root.locator.scan_root)
        .then_some(root)
}

fn direct_child_is_bound_to_root(child: &BoundEntry<'_>, root: &BoundEntry<'_>) -> bool {
    child.entry.scan_id == root.entry.scan_id
        && child.identity.scan_root_id == root.identity.entry_id
        && child.identity.parent_id.as_ref() == Some(&root.identity.entry_id)
        && child.locator.scan_root == root.locator.scan_root
        && child.locator.scan_root_absolute_path == root.locator.scan_root_absolute_path
        && child.locator.parent_reopen_recipe.as_slice() == [root.locator.scan_root.clone()]
        && child.identity.filesystem_object_domain_identity
            == root.identity.filesystem_object_domain_identity
        && child.identity.volume_or_mount_identity == root.identity.volume_or_mount_identity
}

fn bound_cargo_layout_hints(summary: &ScanSummary) -> Vec<BoundCargoLayoutHint<'_>> {
    let mut roots = BTreeMap::<ScanEntryId, BoundEntry<'_>>::new();
    let mut duplicate_roots = BTreeSet::new();
    for entry in &summary.roots {
        let Some(root) = bound_root(entry) else {
            continue;
        };
        if roots.insert(root.identity.entry_id.clone(), root).is_some() {
            duplicate_roots.insert(root.identity.entry_id.clone());
        }
    }
    for duplicate in duplicate_roots {
        roots.remove(&duplicate);
    }

    let mut manifests = BTreeMap::<ScanEntryId, Vec<BoundEntry<'_>>>::new();
    let mut targets = BTreeMap::<ScanEntryId, Vec<BoundEntry<'_>>>::new();
    for entry in &summary.entries {
        let Some(child) = bound_entry(entry) else {
            continue;
        };
        let Some(parent_id) = child.identity.parent_id.as_ref() else {
            continue;
        };
        let Some(root) = roots.get(parent_id) else {
            continue;
        };
        if !direct_child_is_bound_to_root(&child, root) {
            continue;
        }
        match child.entry.object_type {
            ObjectType::File if native_name_eq(&child.entry.native_basename, "Cargo.toml") => {
                manifests.entry(parent_id.clone()).or_default().push(child);
            }
            ObjectType::Directory if native_name_eq(&child.entry.native_basename, "target") => {
                targets.entry(parent_id.clone()).or_default().push(child);
            }
            _ => {}
        }
    }

    roots
        .into_iter()
        .filter_map(|(root_id, root)| {
            let manifest = manifests.get(&root_id)?.as_slice();
            let target = targets.get(&root_id)?.as_slice();
            if manifest.len() != 1 || target.len() != 1 {
                return None;
            }
            Some(BoundCargoLayoutHint {
                root,
                manifest: manifest[0],
                target: target[0],
            })
        })
        .collect()
}

fn native_name_eq(name: &NativeName, expected: &str) -> bool {
    #[cfg(unix)]
    {
        matches!(name, NativeName::UnixBytes(bytes) if bytes.as_slice() == expected.as_bytes())
    }
    #[cfg(windows)]
    {
        let expected_utf16: Vec<u16> = expected.encode_utf16().collect();
        matches!(name, NativeName::WindowsUtf16(units) if units.as_slice() == expected_utf16.as_slice())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (name, expected);
        false
    }
}

fn target_aggregate<'a>(summary: &'a ScanSummary, target: &BoundEntry<'_>) -> AggregateLookup<'a> {
    let target_id = target.identity.entry_id.to_string();
    let mut matching = summary
        .aggregates
        .iter()
        .filter(|aggregate| aggregate.directory_identity == target_id);
    let Some(aggregate) = matching.next() else {
        return AggregateLookup::Missing;
    };
    if matching.next().is_some()
        || aggregate.scan_id != target.entry.scan_id
        || aggregate
            .scan_entry_id()
            .ok()
            .as_ref()
            .is_none_or(|entry_id| entry_id != &target.identity.entry_id)
    {
        return AggregateLookup::Invalid;
    }
    AggregateLookup::Valid(aggregate)
}

fn aggregate_is_final_complete(aggregate: &DirectoryAggregate) -> bool {
    aggregate.coverage.state == CoverageState::Complete
        && aggregate.coverage.complete
        && !aggregate.coverage.details_lost
        && aggregate.coverage.incomplete_reasons.is_empty()
        && matches!(
            aggregate.coverage.provenance,
            FieldProvenance::LiveObservation { .. }
        )
        && aggregate.arithmetic_state == ArithmeticState::Exact
}

fn required_evidence(
    summary: &ScanSummary,
    aggregate: Option<&DirectoryAggregate>,
    cargo: &ExperimentalCargoTypedEvidence,
) -> ExperimentalCargoRequiredEvidence {
    ExperimentalCargoRequiredEvidence {
        workspace: cargo.workspace.state,
        configured_target_dir: cargo.target_dir.state,
        target_shape: cargo.target_shape.state,
        final_complete_aggregate: if aggregate.is_some_and(aggregate_is_final_complete) {
            ExperimentalEvidenceState::Known
        } else {
            ExperimentalEvidenceState::Unknown
        },
        // Boundary rows currently have presentation paths but no scan-entry identity. An empty
        // retained set is useful evidence; a non-empty set cannot safely be assigned to a target.
        no_boundary: if summary.boundaries.is_empty() {
            ExperimentalEvidenceState::Known
        } else {
            ExperimentalEvidenceState::Unknown
        },
        not_shared: cargo.not_shared.state,
        activity: cargo.activity.state,
    }
}

fn build_rule_context(
    layout: &BoundCargoLayoutHint<'_>,
    aggregate: Option<&DirectoryAggregate>,
    cargo: &ExperimentalCargoTypedEvidence,
) -> EvaluationContext {
    let mut context = EvaluationContext::new()
        .insert(
            "candidate.relativePath",
            VmValue::String("target".to_string()),
        )
        .insert(
            "objectType",
            VmValue::String(
                match layout.target.entry.object_type {
                    ObjectType::Directory => "Directory",
                    ObjectType::File => "File",
                    ObjectType::Symlink => "Symlink",
                    ObjectType::ReparsePoint => "ReparsePoint",
                    ObjectType::Other => "Other",
                }
                .to_string(),
            ),
        );
    if let Some(aggregate) = aggregate {
        context = context.insert(
            "coverage.complete",
            VmValue::Bool(aggregate_is_final_complete(aggregate)),
        );
        if matches!(
            aggregate.potentially_reclaimable_bytes,
            EvidenceValue::Known { .. }
        ) {
            context = context.insert(
                "exclusiveReclaimableBytes",
                VmValue::String("known".to_string()),
            );
        }
    }
    if let Some(workspace_id) = cargo.workspace.workspace_id.as_ref() {
        context = context.insert("cargo.workspaceId", VmValue::String(workspace_id.clone()));
    }
    if let Some(target_dir) = cargo.target_dir.relative_path.as_ref() {
        context = context.insert("cargo.targetDir", VmValue::String(target_dir.clone()));
    }
    if let Some(classification) = cargo.target_shape.classification.as_ref() {
        context = context.insert("cargo.targetShape", VmValue::String(classification.clone()));
    }
    // Sharing/activity remain omitted until the corresponding evidence is stronger than not-checked.
    context
}

fn identity_evidence(layout: &BoundCargoLayoutHint<'_>) -> ExperimentalCargoIdentityEvidence {
    ExperimentalCargoIdentityEvidence {
        scan_id: layout.target.entry.scan_id.to_string(),
        root_entry_id: layout.root.identity.entry_id.to_string(),
        manifest_entry_id: layout.manifest.identity.entry_id.to_string(),
        target_entry_id: layout.target.identity.entry_id.to_string(),
        target_parent_entry_id: layout
            .target
            .identity
            .parent_id
            .as_ref()
            .expect("bound direct child has a parent")
            .to_string(),
        native_locator_validated: true,
        root_parent_lineage_bound: true,
        same_filesystem_domain: true,
        same_volume_or_mount: true,
    }
}

fn aggregate_evidence(lookup: &AggregateLookup<'_>) -> ExperimentalCargoAggregateEvidence {
    match lookup {
        AggregateLookup::Valid(aggregate) => ExperimentalCargoAggregateEvidence {
            state: if aggregate_is_final_complete(aggregate) {
                ExperimentalEvidenceState::Known
            } else {
                ExperimentalEvidenceState::Unknown
            },
            revision: Some(aggregate.revision),
            coverage: Some(aggregate.coverage.clone()),
            arithmetic_state: Some(aggregate.arithmetic_state.clone()),
            potentially_reclaimable_bytes: Some(aggregate.potentially_reclaimable_bytes.clone()),
        },
        AggregateLookup::Missing | AggregateLookup::Invalid => ExperimentalCargoAggregateEvidence {
            state: ExperimentalEvidenceState::Unknown,
            revision: None,
            coverage: None,
            arithmetic_state: None,
            potentially_reclaimable_bytes: None,
        },
    }
}

fn observation_reason_codes(
    evaluation: &RuleEvaluation,
    aggregate_lookup: &AggregateLookup<'_>,
    aggregate: Option<&DirectoryAggregate>,
    scan: &ExperimentalCargoScanEvidence,
    cargo: &ExperimentalCargoTypedEvidence,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if cargo.workspace.state != ExperimentalEvidenceState::Known {
        reasons.push(CARGO_WORKSPACE_EVIDENCE_UNKNOWN.to_string());
    }
    if cargo.target_dir.state != ExperimentalEvidenceState::Known {
        reasons.push(CARGO_CONFIG_EVIDENCE_UNKNOWN.to_string());
    }
    if cargo.target_shape.state != ExperimentalEvidenceState::Known {
        reasons.push(CARGO_TARGET_SHAPE_UNKNOWN.to_string());
    }
    match aggregate_lookup {
        AggregateLookup::Missing => reasons.push(TARGET_AGGREGATE_MISSING.to_string()),
        AggregateLookup::Invalid => reasons.push(TARGET_AGGREGATE_INVALID.to_string()),
        AggregateLookup::Valid(aggregate) if !aggregate_is_final_complete(aggregate) => {
            reasons.push(TARGET_AGGREGATE_INCOMPLETE.to_string());
        }
        AggregateLookup::Valid(_) => {}
    }
    if aggregate.is_some_and(|aggregate| {
        !matches!(
            aggregate.potentially_reclaimable_bytes,
            EvidenceValue::Known { .. }
        )
    }) {
        reasons.push(TARGET_RECLAIMABLE_UNKNOWN.to_string());
    }
    if scan.boundary_count != DecimalU128::ZERO {
        reasons.push(SOURCE_SCAN_BOUNDARIES_PRESENT.to_string());
    }
    if scan.incomplete {
        reasons.push(SOURCE_SCAN_INCOMPLETE.to_string());
    }
    if scan.warning_count != DecimalU128::ZERO {
        reasons.push(SOURCE_SCAN_WARNING.to_string());
    }
    reasons.push(
        match evaluation.fact_state {
            EvalState::Known(false) => "cargo_rule_fact_false",
            EvalState::Unknown => "cargo_rule_fact_unknown",
            EvalState::Known(true) => "cargo_rule_fact_true",
        }
        .to_string(),
    );
    reasons.push(
        match evaluation.inference_state {
            EvalState::Known(false) => "cargo_rule_inference_false",
            EvalState::Unknown => "cargo_rule_inference_unknown",
            EvalState::Known(true) => "cargo_rule_inference_true",
        }
        .to_string(),
    );
    reasons
}

fn project_collected_cargo_typed_evidence(
    evidence: &CargoTypedEvidenceV1,
) -> ExperimentalCargoTypedEvidence {
    ExperimentalCargoTypedEvidence {
        workspace: ExperimentalCargoWorkspaceEvidence {
            state: project_state(evidence.workspace_state()),
            reason_code: evidence.workspace_reason_code().map(str::to_string),
            workspace_id: evidence.workspace_id().map(str::to_string),
        },
        config_scope: evidence.config_scope_projection(),
        target_dir: ExperimentalCargoTargetDirEvidence {
            state: project_state(evidence.target_dir_state()),
            reason_code: evidence.target_dir_reason_code().map(str::to_string),
            relative_path: evidence.target_dir_relative_path().map(str::to_string),
        },
        target_shape: ExperimentalCargoTargetShapeEvidence {
            state: project_state(evidence.target_shape_state()),
            reason_code: evidence.target_shape_reason_code().map(str::to_string),
            classification: evidence.target_shape_classification().map(str::to_string),
        },
        not_shared: ExperimentalCargoStateEvidence {
            state: project_state(evidence.not_shared_state()),
            reason_code: evidence.not_shared_reason_code().map(str::to_string),
        },
        activity: ExperimentalCargoStateEvidence {
            state: project_state(evidence.activity_state()),
            reason_code: evidence.activity_reason_code().map(str::to_string),
        },
    }
}

fn project_state(state: CargoEvidenceStateProjection) -> ExperimentalEvidenceState {
    match state {
        CargoEvidenceStateProjection::Known => ExperimentalEvidenceState::Known,
        CargoEvidenceStateProjection::Unknown => ExperimentalEvidenceState::Unknown,
        CargoEvidenceStateProjection::NotChecked => ExperimentalEvidenceState::NotChecked,
    }
}

fn rule_is_a_match(
    evaluation: &RuleEvaluation,
    required: &ExperimentalCargoRequiredEvidence,
    scan: &ExperimentalCargoScanEvidence,
) -> bool {
    evaluation.fact_state.is_true()
        && evaluation.inference_state.is_true()
        && required.supports_rule_match()
        && !scan.incomplete
        && scan.boundary_count == DecimalU128::ZERO
}

fn scan_evidence(
    summary: &ScanSummary,
    source_scan_incomplete: bool,
    source_scan_warning_count: usize,
) -> ExperimentalCargoScanEvidence {
    let error_count = summary
        .progress
        .iter()
        .filter(|event| matches!(event, sweepx_scanner::ProgressEvent::Error { .. }))
        .count();
    let partial_boundary_count = summary
        .boundaries
        .iter()
        .filter(|boundary| {
            !matches!(
                boundary.kind,
                BoundaryKind::Symlink | BoundaryKind::RootSymlink
            )
        })
        .count();
    let incomplete_aggregate_count = summary
        .aggregates
        .iter()
        .filter(|aggregate| !aggregate_is_final_complete(aggregate))
        .count();
    ExperimentalCargoScanEvidence {
        incomplete: source_scan_incomplete
            || error_count > 0
            || partial_boundary_count > 0
            || incomplete_aggregate_count > 0,
        warning_count: DecimalU128::new(source_scan_warning_count as u128),
        error_count: DecimalU128::new(error_count as u128),
        boundary_count: DecimalU128::new(summary.boundaries.len() as u128),
        partial_boundary_count: DecimalU128::new(partial_boundary_count as u128),
        incomplete_aggregate_count: DecimalU128::new(incomplete_aggregate_count as u128),
    }
}

fn eval_state_label(state: EvalState) -> &'static str {
    match state {
        EvalState::Known(true) => "known_true",
        EvalState::Known(false) => "known_false",
        EvalState::Unknown => "unknown",
    }
}

fn risk_label(risk: RiskTier) -> &'static str {
    match risk {
        RiskTier::R1 => "R1",
        RiskTier::R2 => "R2",
        RiskTier::R3 => "R3",
        RiskTier::R4 => "R4",
        RiskTier::Blocked => "BLOCKED",
    }
}

pub fn experimental_cargo_detect_json(result: &ExperimentalCargoDetectResult) -> serde_json::Value {
    json!({
        "command": "cleaner.cargo-detect",
        "experimental": true,
        "liveOnly": true,
        "builtinManifestCompatible": true,
        "matchCount": DecimalU128::new(result.matches.len() as u128),
        "hintCount": DecimalU128::new(result.hints.len() as u128),
        "matches": result.matches,
        "hints": result.hints,
        "reasons": result.reasons,
        "sourceScan": result.scan,
        "readOnly": true,
        "candidateAllowed": false,
        "planAllowed": false,
        "approvalAllowed": false,
        "executionAllowed": false
    })
}

pub fn incompatible_cargo_detect_json() -> serde_json::Value {
    json!({
        "command": "cleaner.cargo-detect",
        "experimental": true,
        "liveOnly": true,
        "scanPerformed": false,
        "builtinManifestCompatible": false,
        "matchCount": DecimalU128::ZERO,
        "hintCount": DecimalU128::ZERO,
        "matches": [],
        "hints": [],
        "reasons": [BUILTIN_MANIFEST_INCOMPATIBLE],
        "readOnly": true,
        "candidateAllowed": false,
        "planAllowed": false,
        "approvalAllowed": false,
        "executionAllowed": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use crate::cargo_cleaner_evidence::cargo_fixed_input_locator_limits;
    use std::path::PathBuf;
    use sweepx_model::{
        Coverage, CoverageState, EvidenceValue, FilesystemObjectDomainIdentity, IdentityEvidence,
        MethodId, NativeAbsolutePath, NativeLocatorEvidence, NativePathComponent,
        PlatformFileIdentity, ReasonCode, ScanId, ScanObjectIdentity, VolumeOrMountIdentity,
    };
    use sweepx_platform::BoundaryRecord;
    #[cfg(target_os = "linux")]
    use sweepx_platform::CancellationToken;
    use sweepx_scanner::ProgressEvent;
    #[cfg(target_os = "linux")]
    use sweepx_scanner::{HostPlatformScanner, LocatorReader};

    fn empty_config_scope_projection() -> CargoConfigScopeProjectionV1 {
        let inputs = crate::cargo_cleaner_evidence::CargoConfigScopeRuntime::from_presence(
            false, false, false,
        );
        crate::cargo_cleaner_evidence::test_config_scope_projection(inputs)
    }

    #[test]
    fn experimental_json_is_read_only_and_uses_separate_hint_projection() {
        let summary = complete_layout_summary();
        let cleaner = compatible_cleaner();
        let result = detect_with_unknown_collector(&summary, &cleaner, false, 0).unwrap();
        let payload = experimental_cargo_detect_json(&result);

        assert_eq!(payload["command"], "cleaner.cargo-detect");
        assert_eq!(payload["experimental"], true);
        assert_eq!(payload["liveOnly"], true);
        assert_eq!(payload["builtinManifestCompatible"], true);
        assert_eq!(payload["matchCount"], "0");
        assert_eq!(payload["hintCount"], "1");
        assert_eq!(payload["readOnly"], true);
        assert_eq!(payload["candidateAllowed"], false);
        assert_eq!(payload["planAllowed"], false);
        assert_eq!(payload["approvalAllowed"], false);
        assert_eq!(payload["executionAllowed"], false);
        let hint = &payload["hints"][0];
        assert_eq!(hint["disposition"], "report_only");
        assert_eq!(hint["executable"], false);
        assert!(hint.get("candidate").is_none());
        assert!(hint.get("resolvedRisk").is_none());
        assert_eq!(hint["ruleEvaluation"]["provisionalRisk"], "R2");
    }

    #[test]
    fn incompatible_projection_has_no_scan_or_rule_results() {
        let payload = incompatible_cargo_detect_json();
        assert_eq!(payload["scanPerformed"], false);
        assert_eq!(payload["builtinManifestCompatible"], false);
        assert_eq!(payload["matchCount"], "0");
        assert_eq!(payload["hintCount"], "0");
        assert_eq!(payload["matches"], json!([]));
        assert_eq!(payload["hints"], json!([]));
        assert_eq!(payload["reasons"][0], BUILTIN_MANIFEST_INCOMPATIBLE);
    }

    #[test]
    fn cargo_name_layout_is_a_hint_because_required_decoders_are_not_implemented() {
        let summary = complete_layout_summary();
        let cleaner = compatible_cleaner();
        let result = detect_with_unknown_collector(&summary, &cleaner, false, 0).unwrap();

        assert!(result.matches.is_empty());
        assert_eq!(result.hints.len(), 1);
        let hint = &result.hints[0];
        assert_eq!(hint.rule_evaluation.fact_state, "unknown");
        assert_eq!(hint.rule_evaluation.inference_state, "known_false");
        assert!(hint.rule_evaluation.report_only);
        assert_eq!(
            hint.evidence.required.workspace,
            ExperimentalEvidenceState::Unknown
        );
        assert_eq!(
            hint.evidence.required.configured_target_dir,
            ExperimentalEvidenceState::Unknown
        );
        assert_eq!(
            hint.evidence.required.target_shape,
            ExperimentalEvidenceState::Unknown
        );
        assert_eq!(
            hint.evidence.required.not_shared,
            ExperimentalEvidenceState::NotChecked
        );
        assert_eq!(
            hint.evidence.required.activity,
            ExperimentalEvidenceState::NotChecked
        );
        assert!(
            hint.reason_codes
                .contains(&CARGO_TARGET_SHAPE_UNKNOWN.to_string())
        );
    }

    #[test]
    fn known_false_fact_state_is_never_a_match() {
        let required = all_required_evidence_known();
        let scan = complete_scan_evidence();
        let false_evaluation = RuleEvaluation {
            fact_state: EvalState::Known(false),
            inference_state: EvalState::Known(true),
            resolved_risk: RiskTier::R2,
            report_only: false,
        };
        assert!(!rule_is_a_match(&false_evaluation, &required, &scan));

        let true_evaluation = RuleEvaluation {
            fact_state: EvalState::Known(true),
            inference_state: EvalState::Known(true),
            resolved_risk: RiskTier::R2,
            report_only: false,
        };
        assert!(rule_is_a_match(&true_evaluation, &required, &scan));
    }

    #[test]
    fn collector_cancellation_has_a_cancelled_terminal_disposition() {
        let summary = complete_layout_summary();
        let cleaner = compatible_cleaner();
        let result = detect_live_cargo_cleaner_candidates_with_collector(
            &summary,
            &cleaner,
            false,
            0,
            |_| {
                let mut evidence = unknown_cargo_projection();
                evidence.workspace.reason_code = Some("cancelled".to_string());
                evidence
            },
        )
        .unwrap();

        assert_eq!(
            result.terminal_disposition(),
            ExperimentalCargoTerminalDisposition::Cancelled
        );
        assert_eq!(result.primary_reason_code(), "cancelled");
    }

    #[test]
    fn incomplete_aggregate_drives_fact_false_and_scan_incomplete() {
        let mut summary = complete_layout_summary();
        let aggregate = summary.aggregates.first_mut().unwrap();
        aggregate.coverage = incomplete_coverage();
        aggregate.arithmetic_state = ArithmeticState::LowerBound;
        aggregate.potentially_reclaimable_bytes = EvidenceValue::LowerBound {
            value: DecimalU128::new(5),
            reason: ReasonCode::IncompleteStreamCoverage,
        };
        let cleaner = compatible_cleaner();
        let result = detect_with_unknown_collector(&summary, &cleaner, true, 1).unwrap();

        assert!(result.matches.is_empty());
        assert_eq!(result.hints.len(), 1);
        let hint = &result.hints[0];
        assert_eq!(hint.rule_evaluation.fact_state, "known_false");
        assert_eq!(
            hint.evidence.required.final_complete_aggregate,
            ExperimentalEvidenceState::Unknown
        );
        assert_eq!(
            hint.evidence.aggregate.arithmetic_state,
            Some(ArithmeticState::LowerBound)
        );
        assert!(
            hint.reason_codes
                .contains(&TARGET_AGGREGATE_INCOMPLETE.to_string())
        );
        assert!(
            hint.reason_codes
                .contains(&TARGET_RECLAIMABLE_UNKNOWN.to_string())
        );
        assert!(result.scan.incomplete);
        assert_eq!(result.scan.incomplete_aggregate_count, DecimalU128::new(1));
    }

    #[test]
    fn missing_aggregate_is_reported_instead_of_using_entry_coverage() {
        let mut summary = complete_layout_summary();
        summary.aggregates.clear();
        assert!(summary.entries[1].coverage.complete);
        let cleaner = compatible_cleaner();
        let result = detect_with_unknown_collector(&summary, &cleaner, false, 0).unwrap();

        assert!(result.matches.is_empty());
        assert_eq!(result.hints.len(), 1);
        assert_eq!(
            result.hints[0].evidence.aggregate.state,
            ExperimentalEvidenceState::Unknown
        );
        assert!(
            result.hints[0]
                .reason_codes
                .contains(&TARGET_AGGREGATE_MISSING.to_string())
        );
    }

    #[test]
    fn source_scan_diagnostics_and_boundary_counts_are_propagated() {
        let mut summary = complete_layout_summary();
        summary.boundaries.push(BoundaryRecord {
            path: PathBuf::from("/scan/root/target/link"),
            kind: BoundaryKind::Symlink,
            reason: ReasonCode::StrictReadOnly,
            detail: "symlink recorded and not followed".to_string(),
        });
        summary.progress.push(ProgressEvent::Error {
            path: PathBuf::from("/scan/root/target/unreadable"),
            reason: ReasonCode::IncompleteStreamCoverage,
        });
        let cleaner = compatible_cleaner();
        let result = detect_with_unknown_collector(&summary, &cleaner, true, 3).unwrap();

        assert!(result.matches.is_empty());
        assert_eq!(result.scan.warning_count, DecimalU128::new(3));
        assert_eq!(result.scan.error_count, DecimalU128::new(1));
        assert_eq!(result.scan.boundary_count, DecimalU128::new(1));
        assert_eq!(result.scan.partial_boundary_count, DecimalU128::ZERO);
        assert!(result.scan.incomplete);
        assert!(result.reasons.contains(&SOURCE_SCAN_WARNING.to_string()));
        assert!(
            result
                .reasons
                .contains(&SOURCE_SCAN_BOUNDARIES_PRESENT.to_string())
        );
    }

    #[test]
    fn cargo_layout_collection_is_globally_bounded() {
        let mut summary = ScanSummary {
            roots: Vec::new(),
            entries: Vec::new(),
            aggregates: Vec::new(),
            boundaries: Vec::new(),
            progress: Vec::new(),
        };
        for index in 0..=CARGO_LAYOUT_LIMIT {
            let base = (index as u128).saturating_mul(3).saturating_add(1);
            let root = root_entry(base, base + 100, base + 200);
            let manifest = child_entry(
                base + 1,
                &root,
                "Cargo.toml",
                ObjectType::File,
                base + 100,
                base + 200,
            );
            let target = child_entry(
                base + 2,
                &root,
                "target",
                ObjectType::Directory,
                base + 100,
                base + 200,
            );
            summary.aggregates.push(target_aggregate_for(&target));
            summary.roots.push(root);
            summary.entries.push(manifest);
            summary.entries.push(target);
        }
        let cleaner = compatible_cleaner();
        let result = detect_with_unknown_collector(&summary, &cleaner, false, 0).unwrap();

        assert_eq!(result.hints.len(), CARGO_LAYOUT_LIMIT);
        assert!(result.scan.incomplete);
        assert!(
            result
                .reasons
                .contains(&CARGO_LAYOUT_LIMIT_REACHED.to_string())
        );
        assert!(result.hints.iter().all(|hint| {
            hint.reason_codes
                .contains(&SOURCE_SCAN_INCOMPLETE.to_string())
        }));
    }

    #[test]
    fn redacted_config_scope_projection_has_stable_shape() {
        let scope = crate::cargo_cleaner_evidence::test_config_scope_projection(
            CargoConfigScopeRuntime::from_presence(true, true, true),
        );
        let wire = serde_json::to_value(scope).unwrap();

        assert_eq!(wire["schema"], "cargo.config-scope.v1");
        assert_eq!(wire["decoderId"], "cargo-workspace-config-v1");
        assert_eq!(wire["precedenceComplete"], false);
        assert_eq!(wire["workspace"]["pairSnapshot"]["state"], "not_checked");
        assert_eq!(wire["workspace"]["config"]["state"], "not_checked");
        assert_eq!(wire["workspace"]["configToml"]["state"], "not_checked");
        assert_eq!(wire["workspace"]["selected"], "not_checked");
        assert_eq!(
            wire["workspace"]["targetDirDeclaration"]["state"],
            "not_checked"
        );
        for key in ["cargoTargetDir", "cargoBuildTargetDir", "cargoHome"] {
            assert_eq!(wire["environment"][key]["state"], "present_redacted");
            assert_eq!(wire["environment"][key]["valueRedacted"], true);
            assert!(wire["environment"][key].get("value").is_none());
        }
        assert_eq!(wire["ancestorConfigs"]["state"], "not_checked");
        assert_eq!(wire["cargoHomeConfig"]["state"], "not_checked");
        assert_eq!(wire["cli"]["targetDir"]["state"], "not_checked");
        assert_eq!(wire["cli"]["configOverrides"]["state"], "not_checked");
        assert_eq!(wire["invocationCwd"]["state"], "not_checked");
        let blockers = wire["blockers"].as_array().unwrap();
        assert!(
            blockers
                .windows(2)
                .all(|pair| pair[0].as_str() < pair[1].as_str())
        );
        assert!(
            blockers
                .iter()
                .any(|value| value == "cargo_target_dir_present_redacted")
        );
        assert!(
            blockers
                .iter()
                .any(|value| value == "cargo_build_target_dir_present_redacted")
        );
        assert!(
            blockers
                .iter()
                .any(|value| value == "cargo_home_present_redacted")
        );
    }

    #[test]
    fn invalid_or_cross_domain_native_binding_is_not_an_observation() {
        let mut missing_locator = complete_layout_summary();
        missing_locator.entries[1].native_locator = None;
        assert_no_layout_observation(missing_locator);

        let mut forged_root = complete_layout_summary();
        forged_root.entries[1]
            .native_locator
            .as_mut()
            .unwrap()
            .scan_root
            .metadata_fingerprint = "forged-root".to_string();
        assert_no_layout_observation(forged_root);

        let root = root_entry(1, 11, 21);
        let manifest = child_entry(2, &root, "Cargo.toml", ObjectType::File, 11, 21);
        let target = child_entry(3, &root, "target", ObjectType::Directory, 12, 21);
        assert_no_layout_observation(summary_with_layout(root, manifest, target, false));

        let root = root_entry(1, 11, 21);
        let manifest = child_entry(2, &root, "Cargo.toml", ObjectType::File, 11, 21);
        let target = child_entry(3, &root, "target", ObjectType::Directory, 11, 22);
        assert_no_layout_observation(summary_with_layout(root, manifest, target, false));
    }

    #[test]
    fn stale_or_unknown_identity_evidence_is_not_an_observation() {
        let mut stale = complete_layout_summary();
        stale.roots[0].provenance = stale_provenance();
        stale.roots[0].coverage.provenance = stale_provenance();
        assert_no_layout_observation(stale);

        let mut unknown_identity = complete_layout_summary();
        unknown_identity.entries[1]
            .identity
            .as_mut()
            .unwrap()
            .filesystem_object_domain_identity =
            IdentityEvidence::unknown(ReasonCode::UnknownIdentity);
        assert_no_layout_observation(unknown_identity);
    }

    #[test]
    fn wrong_root_parent_binding_is_not_accepted_from_matching_path_text() {
        let root = root_entry(1, 11, 21);
        let other_root = root_entry(9, 11, 21);
        let manifest = child_entry(2, &root, "Cargo.toml", ObjectType::File, 11, 21);
        let mut target = child_entry(3, &other_root, "target", ObjectType::Directory, 11, 21);
        target.display_path = "/scan/root/target".to_string();
        let summary = ScanSummary {
            roots: vec![root, other_root],
            entries: vec![manifest, target],
            aggregates: Vec::new(),
            boundaries: Vec::new(),
            progress: Vec::new(),
        };
        assert_no_layout_observation(summary);
    }

    fn assert_no_layout_observation(summary: ScanSummary) {
        let cleaner = compatible_cleaner();
        let result = detect_with_unknown_collector(&summary, &cleaner, false, 0).unwrap();
        assert!(result.matches.is_empty());
        assert!(result.hints.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_collector_projects_workspace_known_but_target_dir_and_shape_not_checked() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
        std::fs::create_dir(root.join("target")).unwrap();
        std::fs::create_dir(root.join("target").join("debug")).unwrap();
        let summary = live_linux_summary(&root, "cargo-detect-linux-known");
        let cleaner = compatible_cleaner();
        let result = detect_live_cargo_cleaner_candidates(
            &summary,
            &cleaner,
            false,
            0,
            &live_reader(),
            CargoConfigScopeRuntime::from_presence(false, false, false),
            &CancellationToken::new(),
        )
        .unwrap();

        assert!(result.matches.is_empty());
        assert_eq!(result.hints.len(), 1);
        let hint = &result.hints[0];
        assert_eq!(
            hint.evidence.cargo.workspace.state,
            ExperimentalEvidenceState::Known
        );
        assert!(hint.evidence.cargo.workspace.workspace_id.is_some());
        let config_scope = serde_json::to_value(&hint.evidence.cargo.config_scope).unwrap();
        assert_eq!(config_scope["schema"], "cargo.config-scope.v1");
        assert_eq!(config_scope["precedenceComplete"], false);
        assert_eq!(
            config_scope["environment"]["cargoTargetDir"]["state"],
            "verified_absent"
        );
        assert_eq!(
            config_scope["environment"]["cargoBuildTargetDir"]["state"],
            "verified_absent"
        );
        assert_eq!(
            hint.evidence.cargo.target_dir.state,
            ExperimentalEvidenceState::NotChecked
        );
        assert_eq!(
            hint.evidence.cargo.target_dir.reason_code.as_deref(),
            Some("config_scope_not_checked")
        );
        assert_eq!(
            hint.evidence.cargo.target_shape.state,
            ExperimentalEvidenceState::Unknown
        );
        assert_eq!(
            hint.evidence.cargo.target_shape.reason_code.as_deref(),
            Some("config_scope_not_checked")
        );
        assert_eq!(
            hint.evidence.required.workspace,
            ExperimentalEvidenceState::Known
        );
        assert_eq!(
            hint.evidence.required.configured_target_dir,
            ExperimentalEvidenceState::NotChecked
        );
        assert_eq!(
            hint.evidence.required.target_shape,
            ExperimentalEvidenceState::Unknown
        );
        assert_eq!(hint.rule_evaluation.fact_state, "unknown");
        assert_eq!(hint.rule_evaluation.inference_state, "known_true");
        assert!(!hint.executable);
    }

    #[test]
    fn stable_json_schema_includes_cargo_projection_without_candidate_or_plan_fields() {
        let summary = complete_layout_summary();
        let cleaner = compatible_cleaner();
        let result = detect_live_cargo_cleaner_candidates_with_collector(
            &summary,
            &cleaner,
            false,
            0,
            |_| known_workspace_not_checked_target_cargo(),
        )
        .unwrap();
        let payload = experimental_cargo_detect_json(&result);
        let hint = &payload["hints"][0];
        assert_eq!(hint["evidence"]["cargo"]["workspace"]["state"], "known");
        assert_eq!(
            hint["evidence"]["cargo"]["configScope"]["schema"],
            "cargo.config-scope.v1"
        );
        assert_eq!(
            hint["evidence"]["cargo"]["configScope"]["precedenceComplete"],
            false
        );
        assert_eq!(
            hint["evidence"]["cargo"]["configScope"]["workspace"]["config"]["state"],
            "not_checked"
        );
        assert_eq!(
            hint["evidence"]["cargo"]["targetDir"]["state"],
            "not_checked"
        );
        assert_eq!(hint["evidence"]["cargo"]["targetShape"]["state"], "unknown");
        assert_eq!(
            hint["evidence"]["cargo"]["notShared"]["reasonCode"],
            "sharing_not_checked"
        );
        assert_eq!(
            hint["evidence"]["cargo"]["activity"]["reasonCode"],
            "activity_not_checked"
        );
        assert!(hint.get("candidate").is_none());
        assert!(hint.get("plan").is_none());
        assert_eq!(payload["candidateAllowed"], false);
        assert_eq!(payload["planAllowed"], false);
        assert_eq!(payload["approvalAllowed"], false);
        assert_eq!(payload["executionAllowed"], false);
    }

    fn detect_with_unknown_collector(
        summary: &ScanSummary,
        cleaner: &LoadedBuiltInCleaner,
        source_scan_incomplete: bool,
        source_scan_warning_count: usize,
    ) -> Result<ExperimentalCargoDetectResult, CoreError> {
        detect_live_cargo_cleaner_candidates_with_collector(
            summary,
            cleaner,
            source_scan_incomplete,
            source_scan_warning_count,
            |_| unknown_cargo_projection(),
        )
    }

    fn unknown_cargo_projection() -> ExperimentalCargoTypedEvidence {
        ExperimentalCargoTypedEvidence {
            workspace: ExperimentalCargoWorkspaceEvidence {
                state: ExperimentalEvidenceState::Unknown,
                reason_code: Some("missing_identity".to_string()),
                workspace_id: None,
            },
            config_scope: empty_config_scope_projection(),
            target_dir: ExperimentalCargoTargetDirEvidence {
                state: ExperimentalEvidenceState::Unknown,
                reason_code: Some("missing_identity".to_string()),
                relative_path: None,
            },
            target_shape: ExperimentalCargoTargetShapeEvidence {
                state: ExperimentalEvidenceState::Unknown,
                reason_code: Some("missing_identity".to_string()),
                classification: None,
            },
            not_shared: ExperimentalCargoStateEvidence {
                state: ExperimentalEvidenceState::NotChecked,
                reason_code: Some("sharing_not_checked".to_string()),
            },
            activity: ExperimentalCargoStateEvidence {
                state: ExperimentalEvidenceState::NotChecked,
                reason_code: Some("activity_not_checked".to_string()),
            },
        }
    }

    fn known_workspace_not_checked_target_cargo() -> ExperimentalCargoTypedEvidence {
        ExperimentalCargoTypedEvidence {
            workspace: ExperimentalCargoWorkspaceEvidence {
                state: ExperimentalEvidenceState::Known,
                reason_code: None,
                workspace_id: Some("scan-cargo-detect:1".to_string()),
            },
            config_scope: empty_config_scope_projection(),
            target_dir: ExperimentalCargoTargetDirEvidence {
                state: ExperimentalEvidenceState::NotChecked,
                reason_code: Some("config_scope_not_checked".to_string()),
                relative_path: None,
            },
            target_shape: ExperimentalCargoTargetShapeEvidence {
                state: ExperimentalEvidenceState::Unknown,
                reason_code: Some("config_scope_not_checked".to_string()),
                classification: None,
            },
            not_shared: ExperimentalCargoStateEvidence {
                state: ExperimentalEvidenceState::NotChecked,
                reason_code: Some("sharing_not_checked".to_string()),
            },
            activity: ExperimentalCargoStateEvidence {
                state: ExperimentalEvidenceState::NotChecked,
                reason_code: Some("activity_not_checked".to_string()),
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn live_reader() -> LocatorReader<HostPlatformScanner> {
        LocatorReader::new(
            HostPlatformScanner::new(),
            cargo_fixed_input_locator_limits(),
        )
    }

    #[cfg(target_os = "linux")]
    fn live_linux_summary(root: &std::path::Path, scan_id: &str) -> ScanSummary {
        use crate::{Scanner, ScannerOptions};
        use sweepx_platform::ScanRoot;

        Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: ScanId::new(scan_id),
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.to_path_buf()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap()
    }

    fn compatible_cleaner() -> LoadedBuiltInCleaner {
        let mut cleaner = crate::load_builtin_cleaners()
            .unwrap()
            .into_iter()
            .find(|cleaner| cleaner.package.manifest.id == CARGO_CLEANER_ID)
            .unwrap();
        cleaner.compatible = true;
        cleaner
    }

    fn all_required_evidence_known() -> ExperimentalCargoRequiredEvidence {
        ExperimentalCargoRequiredEvidence {
            workspace: ExperimentalEvidenceState::Known,
            configured_target_dir: ExperimentalEvidenceState::Known,
            target_shape: ExperimentalEvidenceState::Known,
            final_complete_aggregate: ExperimentalEvidenceState::Known,
            no_boundary: ExperimentalEvidenceState::Known,
            not_shared: ExperimentalEvidenceState::Known,
            activity: ExperimentalEvidenceState::Known,
        }
    }

    fn complete_scan_evidence() -> ExperimentalCargoScanEvidence {
        ExperimentalCargoScanEvidence {
            incomplete: false,
            warning_count: DecimalU128::ZERO,
            error_count: DecimalU128::ZERO,
            boundary_count: DecimalU128::ZERO,
            partial_boundary_count: DecimalU128::ZERO,
            incomplete_aggregate_count: DecimalU128::ZERO,
        }
    }

    fn complete_layout_summary() -> ScanSummary {
        let root = root_entry(1, 11, 21);
        let manifest = child_entry(2, &root, "Cargo.toml", ObjectType::File, 11, 21);
        let target = child_entry(3, &root, "target", ObjectType::Directory, 11, 21);
        summary_with_layout(root, manifest, target, true)
    }

    fn summary_with_layout(
        root: ScannedEntry,
        manifest: ScannedEntry,
        target: ScannedEntry,
        include_aggregate: bool,
    ) -> ScanSummary {
        let aggregates = include_aggregate
            .then(|| target_aggregate_for(&target))
            .into_iter()
            .collect();
        ScanSummary {
            roots: vec![root],
            entries: vec![manifest, target],
            aggregates,
            boundaries: Vec::new(),
            progress: Vec::new(),
        }
    }

    fn target_aggregate_for(target: &ScannedEntry) -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: target.scan_id.clone(),
            directory_identity: target
                .validated_identity()
                .unwrap()
                .unwrap()
                .entry_id
                .to_string(),
            revision: DecimalU128::new(1),
            apparent_logical_bytes: known_bytes(10),
            unique_logical_bytes: known_bytes(10),
            filesystem_reported_allocated_bytes: known_bytes(10),
            potentially_reclaimable_bytes: known_bytes(5),
            direct_child_count: known_bytes(0),
            recursive_entry_count: known_bytes(0),
            coverage: complete_coverage(),
            arithmetic_state: ArithmeticState::Exact,
        }
    }

    fn root_entry(ordinal: u128, domain: u128, mount: u128) -> ScannedEntry {
        let identity = scan_identity(ordinal, ordinal, None, domain, mount);
        let component = native_component(
            &identity,
            native_name("workspace"),
            ObjectType::Directory,
            "root-fingerprint",
        );
        ScannedEntry {
            scan_id: scan_id(),
            identity: Some(identity),
            native_locator: Some(NativeLocatorEvidence {
                scan_root: component.clone(),
                scan_root_absolute_path: Some(native_absolute_root()),
                parent_reopen_recipe: Vec::new(),
                entry: component,
            }),
            display_path: "/scan/root".to_string(),
            native_basename: native_name("workspace"),
            object_type: ObjectType::Directory,
            logical_bytes: known_bytes(10),
            allocated_bytes: known_bytes(10),
            reclaimable_estimate: known_bytes(5),
            metadata_fingerprint: "root-fingerprint".to_string(),
            coverage: complete_coverage(),
            provenance: live_provenance(),
        }
    }

    fn child_entry(
        ordinal: u128,
        root: &ScannedEntry,
        basename: &str,
        object_type: ObjectType,
        domain: u128,
        mount: u128,
    ) -> ScannedEntry {
        let root_identity = root.validated_identity().unwrap().unwrap();
        let root_locator = root.validated_native_locator().unwrap().unwrap();
        let identity = scan_identity(
            ordinal,
            entry_ordinal(&root_identity.entry_id),
            Some(entry_ordinal(&root_identity.entry_id)),
            domain,
            mount,
        );
        let fingerprint = format!("{basename}-fingerprint");
        let native_basename = native_name(basename);
        let entry_component = native_component(
            &identity,
            native_basename.clone(),
            object_type.clone(),
            &fingerprint,
        );
        ScannedEntry {
            scan_id: scan_id(),
            identity: Some(identity),
            native_locator: Some(NativeLocatorEvidence {
                scan_root: root_locator.scan_root.clone(),
                scan_root_absolute_path: root_locator.scan_root_absolute_path.clone(),
                parent_reopen_recipe: vec![root_locator.scan_root.clone()],
                entry: entry_component,
            }),
            display_path: format!("/scan/root/{basename}"),
            native_basename,
            object_type,
            logical_bytes: known_bytes(10),
            allocated_bytes: known_bytes(10),
            reclaimable_estimate: known_bytes(5),
            metadata_fingerprint: fingerprint,
            coverage: complete_coverage(),
            provenance: live_provenance(),
        }
    }

    fn scan_identity(
        ordinal: u128,
        root_ordinal: u128,
        parent_ordinal: Option<u128>,
        domain: u128,
        mount: u128,
    ) -> ScanObjectIdentity {
        ScanObjectIdentity {
            entry_id: scan_entry_id(ordinal),
            scan_root_id: scan_entry_id(root_ordinal),
            parent_id: parent_ordinal.map(scan_entry_id),
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(domain),
                inode: DecimalU128::new(ordinal),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(domain),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(mount),
            }),
        }
    }

    fn native_component(
        identity: &ScanObjectIdentity,
        native_basename: NativeName,
        object_type: ObjectType,
        metadata_fingerprint: &str,
    ) -> NativePathComponent {
        NativePathComponent {
            entry_id: identity.entry_id.clone(),
            parent_id: identity.parent_id.clone(),
            native_basename,
            object_type,
            platform_file_identity: identity.platform_file_identity.clone(),
            filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
            metadata_fingerprint: metadata_fingerprint.to_string(),
        }
    }

    fn complete_coverage() -> Coverage {
        Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: Vec::new(),
            details_lost: false,
            provenance: live_provenance(),
        }
    }

    fn incomplete_coverage() -> Coverage {
        Coverage {
            state: CoverageState::Incomplete,
            complete: false,
            incomplete_reasons: vec![ReasonCode::IncompleteStreamCoverage],
            details_lost: false,
            provenance: live_provenance(),
        }
    }

    fn known_bytes(value: u128) -> EvidenceValue<DecimalU128> {
        EvidenceValue::Known {
            value: DecimalU128::new(value),
        }
    }

    fn live_provenance() -> FieldProvenance {
        FieldProvenance::LiveObservation {
            observed_at: "2026-08-27T00:00:00Z".to_string(),
            method: MethodId::NativeApi,
        }
    }

    fn stale_provenance() -> FieldProvenance {
        FieldProvenance::StalePreview {
            observed_at: "2026-08-27T00:00:00Z".to_string(),
        }
    }

    fn scan_id() -> ScanId {
        ScanId::new("scan-cargo-detect")
    }

    fn scan_entry_id(ordinal: u128) -> ScanEntryId {
        ScanEntryId::for_scan_ordinal(&scan_id(), ordinal).unwrap()
    }

    fn entry_ordinal(id: &ScanEntryId) -> u128 {
        id.as_str().rsplit_once(':').unwrap().1.parse().unwrap()
    }

    fn native_name(name: &str) -> NativeName {
        #[cfg(unix)]
        {
            NativeName::unix(name.as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            NativeName::windows_utf16(name.encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeName::unix(name.as_bytes().to_vec())
        }
    }

    fn native_absolute_root() -> NativeAbsolutePath {
        #[cfg(unix)]
        {
            NativeAbsolutePath::unix(b"/scan/root".to_vec())
        }
        #[cfg(windows)]
        {
            NativeAbsolutePath::windows_utf16(r"C:\scan\root".encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeAbsolutePath::unix(b"/scan/root".to_vec())
        }
    }
}
