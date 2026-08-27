use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sweepx_model::{
    ArithmeticState, ByteValue, CandidateId, Coverage, CoverageState, DecimalU128,
    DirectoryAggregate, EvidenceValue, FieldProvenance, NativeLocatorEvidence, NativeName,
    ObjectType, ReasonCode, RiskTier, ScanId, ScanObjectIdentity, ScannedEntry,
};

use crate::digest::{AnalysisDigestError, analysis_digest_hex};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PathPresentation {
    pub display_path: String,
    pub native_basename: NativeName,
    pub stable_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CandidateLocator {
    pub stable_identity: Option<String>,
    pub scan_object_identity: Option<ScanObjectIdentity>,
    pub native_locator: Option<NativeLocatorEvidence>,
    pub native_basename: NativeName,
    pub metadata_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSourceState {
    Live,
    ValidatedCurrent,
    DerivedCurrent,
    Stale,
    Unknown,
}

impl CandidateSourceState {
    pub fn from_provenance(provenance: &FieldProvenance) -> Self {
        match provenance {
            FieldProvenance::LiveObservation { .. } => Self::Live,
            FieldProvenance::ValidatedCache { .. } => Self::ValidatedCurrent,
            FieldProvenance::DerivedFromCurrent { .. } => Self::DerivedCurrent,
            FieldProvenance::StalePreview { .. } => Self::Stale,
            FieldProvenance::Unknown { .. } => Self::Unknown,
        }
    }

    pub fn is_current(self) -> bool {
        matches!(
            self,
            Self::Live | Self::ValidatedCurrent | Self::DerivedCurrent
        )
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Live)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableEligibility {
    Executable,
    ReportOnly,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CandidateEligibility {
    pub executable: ExecutableEligibility,
    pub reasons: Vec<ReasonCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FactPresence {
    Present,
    Partial,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InferenceStrength {
    Weak,
    Moderate,
    Strong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownImpact {
    RaisesToR4,
    Blocks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationKind {
    Fact,
    Inference,
    Heuristic,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ExplanationClause {
    pub kind: ExplanationKind,
    pub code: String,
    pub message: String,
    pub reason: Option<ReasonCode>,
    pub fact_presence: Option<FactPresence>,
    pub inference_strength: Option<InferenceStrength>,
    pub unknown_impact: Option<UnknownImpact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RiskSignal {
    Fact {
        code: String,
    },
    Inference {
        code: String,
    },
    Heuristic {
        code: String,
        reason: Option<ReasonCode>,
    },
    Unknown {
        code: String,
        reason: Option<ReasonCode>,
    },
    CoverageIncomplete {
        reason: ReasonCode,
    },
    CoverageDetailsLost,
    SourceNotCurrent,
    LiveSourceMissing,
    BlockedReason {
        reason: ReasonCode,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RiskAssessment {
    pub tier: RiskTier,
    pub signals: Vec<RiskSignal>,
}

pub struct MonotonicClassifier;

impl MonotonicClassifier {
    pub fn classify(signals: &[RiskSignal]) -> RiskAssessment {
        let mut tier = RiskTier::R1;
        for signal in signals {
            tier = Self::elevate(tier, Self::minimum_tier(signal));
        }
        RiskAssessment {
            tier,
            signals: signals.to_vec(),
        }
    }

    pub fn elevate(current: RiskTier, next: RiskTier) -> RiskTier {
        use RiskTier::{Blocked, R1, R2, R3, R4};

        let rank = |tier| match tier {
            R1 => 1_u8,
            R2 => 2,
            R3 => 3,
            R4 => 4,
            Blocked => 5,
        };

        if rank(next) > rank(current) {
            next
        } else {
            current
        }
    }

    fn minimum_tier(signal: &RiskSignal) -> RiskTier {
        match signal {
            RiskSignal::Fact { .. } => RiskTier::R1,
            RiskSignal::Inference { .. } => RiskTier::R2,
            RiskSignal::Heuristic { .. } => RiskTier::R2,
            RiskSignal::CoverageIncomplete { .. }
            | RiskSignal::SourceNotCurrent
            | RiskSignal::LiveSourceMissing => RiskTier::R3,
            RiskSignal::CoverageDetailsLost | RiskSignal::Unknown { .. } => RiskTier::R4,
            RiskSignal::BlockedReason { .. } => RiskTier::Blocked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CandidateDigestInput {
    pub scan_id: ScanId,
    pub object_type: ObjectType,
    pub locator: CandidateLocator,
    pub provenance: FieldProvenance,
    pub source_state: CandidateSourceState,
    pub live_source_required: bool,
    pub logical_bytes: ByteValue,
    pub allocated_bytes: ByteValue,
    pub reclaimable_estimate: ByteValue,
    pub coverage: Coverage,
    pub aggregate_directory_identity: Option<String>,
    pub aggregate_revision: Option<DecimalU128>,
    pub aggregate_coverage: Option<Coverage>,
    pub aggregate_arithmetic_state: Option<ArithmeticState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Candidate {
    pub candidate_id: CandidateId,
    pub canonical_digest: String,
    pub scan_id: ScanId,
    pub object_type: ObjectType,
    pub metadata_fingerprint: String,
    pub path: PathPresentation,
    pub locator: CandidateLocator,
    pub provenance: FieldProvenance,
    pub source_state: CandidateSourceState,
    pub live_source_required: bool,
    pub logical_bytes: ByteValue,
    pub allocated_bytes: ByteValue,
    pub reclaimable_estimate: ByteValue,
    pub coverage: Coverage,
    pub aggregate_directory_identity: Option<String>,
    pub aggregate_revision: Option<DecimalU128>,
    pub aggregate_coverage: Option<Coverage>,
    pub aggregate_arithmetic_state: Option<ArithmeticState>,
    pub risk: RiskAssessment,
    pub eligibility: CandidateEligibility,
}

impl Candidate {
    pub fn digest_input(&self) -> CandidateDigestInput {
        CandidateDigestInput {
            scan_id: self.scan_id.clone(),
            object_type: self.object_type.clone(),
            locator: self.locator.clone(),
            provenance: self.provenance.clone(),
            source_state: self.source_state,
            live_source_required: self.live_source_required,
            logical_bytes: self.logical_bytes.clone(),
            allocated_bytes: self.allocated_bytes.clone(),
            reclaimable_estimate: self.reclaimable_estimate.clone(),
            coverage: self.coverage.clone(),
            aggregate_directory_identity: self.aggregate_directory_identity.clone(),
            aggregate_revision: self.aggregate_revision,
            aggregate_coverage: self.aggregate_coverage.clone(),
            aggregate_arithmetic_state: self.aggregate_arithmetic_state.clone(),
        }
    }
}

pub struct CandidateBuilder<'a> {
    entry: &'a ScannedEntry,
    aggregate_link: Option<AggregateLink<'a>>,
    live_source_required: bool,
}

impl<'a> CandidateBuilder<'a> {
    pub fn new(entry: &'a ScannedEntry) -> Self {
        Self {
            entry,
            aggregate_link: None,
            live_source_required: true,
        }
    }

    pub fn with_aggregate(
        mut self,
        aggregate: &'a DirectoryAggregate,
        directory_identity: impl Into<String>,
    ) -> Self {
        self.aggregate_link = Some(AggregateLink {
            aggregate: Some(aggregate),
            directory_identity: directory_identity.into(),
        });
        self
    }

    pub fn with_expected_directory_identity(
        mut self,
        directory_identity: impl Into<String>,
    ) -> Self {
        self.aggregate_link = Some(AggregateLink {
            aggregate: None,
            directory_identity: directory_identity.into(),
        });
        self
    }

    pub fn live_source_required(mut self, required: bool) -> Self {
        self.live_source_required = required;
        self
    }

    pub fn build(self) -> Result<Candidate, AnalysisDigestError> {
        let source_state = CandidateSourceState::from_provenance(&self.entry.provenance);
        let scan_object_identity = self.entry.validated_identity().ok().flatten().cloned();
        let native_locator = self
            .entry
            .validated_native_locator()
            .ok()
            .flatten()
            .cloned();
        let stable_identity = scan_object_identity
            .as_ref()
            .map(|identity| identity.entry_id.to_string());
        let path = PathPresentation {
            display_path: self.entry.display_path.clone(),
            native_basename: self.entry.native_basename.clone(),
            stable_identity: stable_identity.clone(),
        };
        let locator = CandidateLocator {
            stable_identity,
            scan_object_identity: scan_object_identity.clone(),
            native_locator,
            native_basename: self.entry.native_basename.clone(),
            metadata_fingerprint: self.entry.metadata_fingerprint.clone(),
        };
        let aggregate_link_requested = self.aggregate_link.is_some();
        let aggregate = self.aggregate_link.as_ref().and_then(|link| {
            let aggregate = link.aggregate?;
            let identity = scan_object_identity.as_ref()?;
            let aggregate_entry_id = aggregate.scan_entry_id().ok()?;
            (aggregate.scan_id == self.entry.scan_id
                && aggregate_entry_id == identity.entry_id
                && link.directory_identity == aggregate.directory_identity)
                .then_some(aggregate)
        });

        let risk_signals = collect_risk_signals(
            self.entry,
            aggregate,
            aggregate_link_requested,
            scan_object_identity.is_some(),
            source_state,
            self.live_source_required,
        );
        let risk = MonotonicClassifier::classify(&risk_signals);
        let eligibility = evaluate_eligibility(EligibilityInput {
            directory_requires_aggregate: self.entry.object_type == ObjectType::Directory,
            entry_coverage: &self.entry.coverage,
            aggregate_coverage: aggregate.map(|aggregate| &aggregate.coverage),
            aggregate_linked: aggregate_link_requested,
            identity_valid: scan_object_identity.is_some(),
            native_locator_valid: digest_input_locator_has_native_locator(&locator),
            source_state,
            live_source_required: self.live_source_required,
        });

        let digest_input = CandidateDigestInput {
            scan_id: self.entry.scan_id.clone(),
            object_type: self.entry.object_type.clone(),
            locator,
            provenance: self.entry.provenance.clone(),
            source_state,
            live_source_required: self.live_source_required,
            logical_bytes: self.entry.logical_bytes.clone(),
            allocated_bytes: self.entry.allocated_bytes.clone(),
            reclaimable_estimate: self.entry.reclaimable_estimate.clone(),
            coverage: self.entry.coverage.clone(),
            aggregate_directory_identity: aggregate
                .map(|aggregate| aggregate.directory_identity.clone()),
            aggregate_revision: aggregate.map(|aggregate| aggregate.revision),
            aggregate_coverage: aggregate.map(|aggregate| aggregate.coverage.clone()),
            aggregate_arithmetic_state: aggregate
                .map(|aggregate| aggregate.arithmetic_state.clone()),
        };

        let canonical_digest = analysis_digest_hex(&digest_input)?;

        Ok(Candidate {
            candidate_id: CandidateId::new(format!("cand-{}", &canonical_digest[..16])),
            canonical_digest,
            scan_id: digest_input.scan_id.clone(),
            object_type: digest_input.object_type.clone(),
            metadata_fingerprint: digest_input.locator.metadata_fingerprint.clone(),
            path,
            locator: digest_input.locator,
            provenance: digest_input.provenance,
            source_state: digest_input.source_state,
            live_source_required: digest_input.live_source_required,
            logical_bytes: digest_input.logical_bytes,
            allocated_bytes: digest_input.allocated_bytes,
            reclaimable_estimate: digest_input.reclaimable_estimate,
            coverage: digest_input.coverage,
            aggregate_directory_identity: digest_input.aggregate_directory_identity,
            aggregate_revision: digest_input.aggregate_revision,
            aggregate_coverage: digest_input.aggregate_coverage,
            aggregate_arithmetic_state: digest_input.aggregate_arithmetic_state,
            risk,
            eligibility,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ExplanationDigestInput {
    pub candidate_digest: String,
    pub risk: RiskAssessment,
    pub eligibility: CandidateEligibility,
    pub clauses: Vec<ExplanationClause>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Explanation {
    pub candidate_id: CandidateId,
    pub candidate_digest: String,
    pub canonical_digest: String,
    pub risk: RiskAssessment,
    pub eligibility: CandidateEligibility,
    pub clauses: Vec<ExplanationClause>,
}

impl Explanation {
    pub fn digest_input(&self) -> ExplanationDigestInput {
        ExplanationDigestInput {
            candidate_digest: self.candidate_digest.clone(),
            risk: self.risk.clone(),
            eligibility: self.eligibility.clone(),
            clauses: self.clauses.clone(),
        }
    }

    pub fn facts(&self) -> Vec<&ExplanationClause> {
        self.clauses
            .iter()
            .filter(|clause| clause.kind == ExplanationKind::Fact)
            .collect()
    }

    pub fn inferences(&self) -> Vec<&ExplanationClause> {
        self.clauses
            .iter()
            .filter(|clause| clause.kind == ExplanationKind::Inference)
            .collect()
    }

    pub fn heuristics(&self) -> Vec<&ExplanationClause> {
        self.clauses
            .iter()
            .filter(|clause| clause.kind == ExplanationKind::Heuristic)
            .collect()
    }

    pub fn unknowns(&self) -> Vec<&ExplanationClause> {
        self.clauses
            .iter()
            .filter(|clause| clause.kind == ExplanationKind::Unknown)
            .collect()
    }
}

pub struct ExplanationBuilder<'a> {
    candidate: &'a Candidate,
    clauses: Vec<ExplanationClause>,
}

impl<'a> ExplanationBuilder<'a> {
    pub fn new(candidate: &'a Candidate) -> Self {
        Self {
            candidate,
            clauses: Vec::new(),
        }
    }

    pub fn with_clause(mut self, clause: ExplanationClause) -> Self {
        self.clauses.push(clause);
        self
    }

    pub fn extend_clauses<I>(mut self, clauses: I) -> Self
    where
        I: IntoIterator<Item = ExplanationClause>,
    {
        self.clauses.extend(clauses);
        self
    }

    pub fn build(self) -> Result<Explanation, AnalysisDigestError> {
        let digest_input = ExplanationDigestInput {
            candidate_digest: self.candidate.canonical_digest.clone(),
            risk: self.candidate.risk.clone(),
            eligibility: self.candidate.eligibility.clone(),
            clauses: self.clauses,
        };
        let canonical_digest = analysis_digest_hex(&digest_input)?;

        Ok(Explanation {
            candidate_id: self.candidate.candidate_id.clone(),
            candidate_digest: self.candidate.canonical_digest.clone(),
            canonical_digest,
            risk: digest_input.risk,
            eligibility: digest_input.eligibility,
            clauses: digest_input.clauses,
        })
    }
}

fn collect_risk_signals(
    entry: &ScannedEntry,
    aggregate: Option<&DirectoryAggregate>,
    aggregate_linked: bool,
    identity_valid: bool,
    source_state: CandidateSourceState,
    live_source_required: bool,
) -> Vec<RiskSignal> {
    let mut signals = vec![RiskSignal::Fact {
        code: "entry_present".to_string(),
    }];

    match source_state {
        CandidateSourceState::Live => {}
        CandidateSourceState::ValidatedCurrent | CandidateSourceState::DerivedCurrent => {
            if live_source_required {
                signals.push(RiskSignal::LiveSourceMissing);
            }
        }
        CandidateSourceState::Stale => signals.push(RiskSignal::SourceNotCurrent),
        CandidateSourceState::Unknown => {
            signals.push(RiskSignal::SourceNotCurrent);
            signals.push(RiskSignal::Unknown {
                code: "source_provenance_unknown".to_string(),
                reason: Some(ReasonCode::Unknown),
            });
        }
    }

    push_value_signals(&mut signals, "logical_bytes", &entry.logical_bytes);
    push_value_signals(&mut signals, "allocated_bytes", &entry.allocated_bytes);
    push_value_signals(
        &mut signals,
        "reclaimable_estimate",
        &entry.reclaimable_estimate,
    );
    push_coverage_signals(&mut signals, &entry.coverage);
    if !identity_valid {
        signals.push(RiskSignal::Unknown {
            code: "scan_object_identity_missing_or_invalid".to_string(),
            reason: Some(ReasonCode::UnknownIdentity),
        });
    }

    if let Some(aggregate) = aggregate {
        push_coverage_signals(&mut signals, &aggregate.coverage);
        match aggregate.arithmetic_state {
            ArithmeticState::Exact => signals.push(RiskSignal::Fact {
                code: "aggregate_exact".to_string(),
            }),
            ArithmeticState::LowerBound => signals.push(RiskSignal::Heuristic {
                code: "aggregate_lower_bound".to_string(),
                reason: Some(ReasonCode::IncompleteStreamCoverage),
            }),
            ArithmeticState::Overflowed => signals.push(RiskSignal::Unknown {
                code: "aggregate_overflowed".to_string(),
                reason: Some(ReasonCode::Overflow),
            }),
            ArithmeticState::Unknown => signals.push(RiskSignal::Unknown {
                code: "aggregate_unknown".to_string(),
                reason: Some(ReasonCode::Unknown),
            }),
        }
    } else if entry.object_type == ObjectType::Directory {
        signals.push(RiskSignal::Unknown {
            code: if aggregate_linked {
                "aggregate_link_missing_target".to_string()
            } else {
                "aggregate_link_not_supplied".to_string()
            },
            reason: Some(ReasonCode::UnknownIdentity),
        });
    }

    signals
}

fn push_coverage_signals(signals: &mut Vec<RiskSignal>, coverage: &Coverage) {
    if !coverage.complete {
        for reason in &coverage.incomplete_reasons {
            signals.push(RiskSignal::CoverageIncomplete {
                reason: reason.clone(),
            });
        }
    }
    if coverage.details_lost || coverage.state == CoverageState::DetailsLost {
        signals.push(RiskSignal::CoverageDetailsLost);
    }
}

fn push_value_signals(signals: &mut Vec<RiskSignal>, code: &str, value: &ByteValue) {
    match value {
        EvidenceValue::Known { .. } => signals.push(RiskSignal::Fact {
            code: code.to_string(),
        }),
        EvidenceValue::LowerBound { reason, .. } => signals.push(RiskSignal::Heuristic {
            code: code.to_string(),
            reason: Some(reason.clone()),
        }),
        EvidenceValue::Unknown { reason }
        | EvidenceValue::Unsupported { reason }
        | EvidenceValue::NotChecked { reason } => {
            let signal = if blocks_execution(reason) {
                RiskSignal::BlockedReason {
                    reason: reason.clone(),
                }
            } else {
                RiskSignal::Unknown {
                    code: code.to_string(),
                    reason: Some(reason.clone()),
                }
            };
            signals.push(signal);
        }
    }
}

struct EligibilityInput<'a> {
    directory_requires_aggregate: bool,
    entry_coverage: &'a Coverage,
    aggregate_coverage: Option<&'a Coverage>,
    aggregate_linked: bool,
    identity_valid: bool,
    native_locator_valid: bool,
    source_state: CandidateSourceState,
    live_source_required: bool,
}

fn evaluate_eligibility(input: EligibilityInput<'_>) -> CandidateEligibility {
    let mut reasons = Vec::new();
    let mut executable = ExecutableEligibility::Executable;

    collect_incomplete_reasons(&mut reasons, input.entry_coverage);
    if let Some(aggregate_coverage) = input.aggregate_coverage {
        collect_incomplete_reasons(&mut reasons, aggregate_coverage);
    }

    if input.entry_coverage.details_lost
        || input.entry_coverage.state == CoverageState::DetailsLost
        || input
            .aggregate_coverage
            .map(|coverage| coverage.details_lost || coverage.state == CoverageState::DetailsLost)
            .unwrap_or(false)
    {
        executable = ExecutableEligibility::Blocked;
    }

    if (input.live_source_required && !input.source_state.is_live())
        || !input.source_state.is_current()
    {
        executable = downgrade(executable, ExecutableEligibility::ReportOnly);
        reasons.push(ReasonCode::NotRevalidated);
    }

    if (input.directory_requires_aggregate || input.aggregate_linked)
        && input.aggregate_coverage.is_none()
    {
        executable = downgrade(executable, ExecutableEligibility::ReportOnly);
        reasons.push(ReasonCode::UnknownIdentity);
    }

    if !input.identity_valid {
        executable = downgrade(executable, ExecutableEligibility::ReportOnly);
        reasons.push(ReasonCode::UnknownIdentity);
    }

    if !input.native_locator_valid {
        executable = downgrade(executable, ExecutableEligibility::ReportOnly);
        reasons.push(ReasonCode::UnknownIdentity);
    }

    if !reasons.is_empty() && executable == ExecutableEligibility::Executable {
        executable = ExecutableEligibility::ReportOnly;
    }

    CandidateEligibility {
        executable,
        reasons,
    }
}

fn digest_input_locator_has_native_locator(locator: &CandidateLocator) -> bool {
    locator.native_locator.is_some()
}

fn collect_incomplete_reasons(reasons: &mut Vec<ReasonCode>, coverage: &Coverage) {
    if !coverage.complete {
        reasons.extend(coverage.incomplete_reasons.iter().cloned());
    }
}

fn downgrade(current: ExecutableEligibility, next: ExecutableEligibility) -> ExecutableEligibility {
    match (current, next) {
        (ExecutableEligibility::Blocked, _) | (_, ExecutableEligibility::Blocked) => {
            ExecutableEligibility::Blocked
        }
        (ExecutableEligibility::ReportOnly, _) | (_, ExecutableEligibility::ReportOnly) => {
            ExecutableEligibility::ReportOnly
        }
        _ => ExecutableEligibility::Executable,
    }
}

fn blocks_execution(reason: &ReasonCode) -> bool {
    matches!(
        reason,
        ReasonCode::IdentityUnstable
            | ReasonCode::UnsupportedPlatform
            | ReasonCode::UnsupportedFilesystem
            | ReasonCode::AdapterCapabilityAbsent
            | ReasonCode::StrictReadOnly
    )
}

struct AggregateLink<'a> {
    aggregate: Option<&'a DirectoryAggregate>,
    directory_identity: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweepx_model::{
        Coverage, FilesystemObjectDomainIdentity, IdentityEvidence, MethodId,
        NativeLocatorEvidence, NativePathComponent, PlatformFileIdentity, ScanEntryId,
        ScanObjectIdentity, VolumeOrMountIdentity,
    };

    fn live_provenance() -> FieldProvenance {
        FieldProvenance::LiveObservation {
            observed_at: "2026-08-26T00:00:00Z".to_string(),
            method: MethodId::NativeApi,
        }
    }

    fn stale_provenance() -> FieldProvenance {
        FieldProvenance::StalePreview {
            observed_at: "2026-08-20T00:00:00Z".to_string(),
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

    fn entry(
        display_path: &str,
        metadata_fingerprint: &str,
        provenance: FieldProvenance,
        object_type: ObjectType,
        identity: Option<ScanObjectIdentity>,
    ) -> ScannedEntry {
        let native_basename = NativeName::unix(b"demo".to_vec());
        let native_locator = identity
            .as_ref()
            .map(|identity| native_locator(identity, native_basename.clone()));
        ScannedEntry {
            scan_id: ScanId::new("scan-1"),
            identity,
            native_locator,
            display_path: display_path.to_string(),
            native_basename,
            object_type,
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(10),
            },
            allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::new(12),
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: DecimalU128::new(4),
            },
            metadata_fingerprint: metadata_fingerprint.to_string(),
            coverage: complete_coverage(),
            provenance,
        }
    }

    fn entry_with_native_locator(
        display_path: &str,
        metadata_fingerprint: &str,
        provenance: FieldProvenance,
        object_type: ObjectType,
        identity: Option<ScanObjectIdentity>,
        native_locator: Option<NativeLocatorEvidence>,
    ) -> ScannedEntry {
        let mut entry = entry(
            display_path,
            metadata_fingerprint,
            provenance,
            object_type,
            identity,
        );
        entry.native_locator = native_locator;
        entry
    }

    fn identity(entry_ordinal: u128, root_ordinal: u128) -> ScanObjectIdentity {
        let scan_id = ScanId::new("scan-1");
        let entry_id = ScanEntryId::for_scan_ordinal(&scan_id, entry_ordinal).unwrap();
        let scan_root_id = ScanEntryId::for_scan_ordinal(&scan_id, root_ordinal).unwrap();
        ScanObjectIdentity {
            parent_id: (entry_id != scan_root_id).then(|| scan_root_id.clone()),
            entry_id,
            scan_root_id,
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(entry_ordinal),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(1),
            }),
        }
    }

    fn native_locator(
        identity: &ScanObjectIdentity,
        entry_native_basename: NativeName,
    ) -> NativeLocatorEvidence {
        NativeLocatorEvidence {
            scan_root: NativePathComponent {
                entry_id: identity.scan_root_id.clone(),
                native_basename: NativeName::unix(b"root".to_vec()),
            },
            parent_reopen_recipe: identity
                .parent_id
                .as_ref()
                .map(|parent_id| NativePathComponent {
                    entry_id: parent_id.clone(),
                    native_basename: NativeName::unix(b"parent".to_vec()),
                })
                .into_iter()
                .collect(),
            entry: NativePathComponent {
                entry_id: identity.entry_id.clone(),
                native_basename: entry_native_basename,
            },
        }
    }

    fn aggregate(identity: &str, coverage: Coverage, revision: u128) -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: ScanId::new("scan-1"),
            directory_identity: identity.to_string(),
            revision: DecimalU128::new(revision),
            apparent_logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(10),
            },
            unique_logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(10),
            },
            filesystem_reported_allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::new(12),
            },
            potentially_reclaimable_bytes: EvidenceValue::Known {
                value: DecimalU128::new(4),
            },
            direct_child_count: EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            recursive_entry_count: EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            coverage,
            arithmetic_state: ArithmeticState::Exact,
        }
    }

    #[test]
    fn candidate_digest_is_stable_across_equivalent_inputs() {
        let aggregate = aggregate("dir-1", complete_coverage(), 1);
        let first = CandidateBuilder::new(&entry(
            "/tmp/a",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            Some(identity(2, 1)),
        ))
        .with_aggregate(&aggregate, "dir-1")
        .build()
        .unwrap();
        let second = CandidateBuilder::new(&entry(
            "/tmp/a",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            Some(identity(2, 1)),
        ))
        .with_aggregate(&aggregate, "dir-1")
        .build()
        .unwrap();

        assert_eq!(first.canonical_digest, second.canonical_digest);
        assert_eq!(first.candidate_id, second.candidate_id);
    }

    #[test]
    fn unknown_signals_never_lower_risk() {
        let base = MonotonicClassifier::classify(&[RiskSignal::Inference {
            code: "derived".to_string(),
        }]);
        let elevated = MonotonicClassifier::classify(&[
            RiskSignal::Inference {
                code: "derived".to_string(),
            },
            RiskSignal::Unknown {
                code: "unknown".to_string(),
                reason: Some(ReasonCode::Unknown),
            },
        ]);

        assert_eq!(base.tier, RiskTier::R2);
        assert_eq!(elevated.tier, RiskTier::R4);
    }

    #[test]
    fn incomplete_coverage_blocks_executable_eligibility() {
        let mut scanned = entry(
            "/tmp/a",
            "fp-1",
            live_provenance(),
            ObjectType::File,
            Some(identity(2, 1)),
        );
        scanned.coverage = incomplete_coverage();

        let candidate = CandidateBuilder::new(&scanned).build().unwrap();

        assert_eq!(
            candidate.eligibility.executable,
            ExecutableEligibility::ReportOnly
        );
        assert!(
            candidate
                .eligibility
                .reasons
                .contains(&ReasonCode::IncompleteStreamCoverage)
        );
    }

    #[test]
    fn path_display_is_not_used_as_identity() {
        let entry_identity = identity(2, 1);
        let aggregate = aggregate(entry_identity.entry_id.as_str(), complete_coverage(), 1);
        let candidate = CandidateBuilder::new(&entry(
            "/tmp/one",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            Some(entry_identity.clone()),
        ))
        .with_aggregate(&aggregate, entry_identity.entry_id.as_str())
        .build()
        .unwrap();

        assert_eq!(candidate.path.display_path, "/tmp/one");
        assert_eq!(
            candidate.path.stable_identity.as_deref(),
            Some(entry_identity.entry_id.as_str())
        );
        assert_ne!(
            candidate.path.stable_identity.as_deref(),
            Some(candidate.path.display_path.as_str())
        );
    }

    #[test]
    fn source_not_current_forces_report_only_when_live_required() {
        let candidate = CandidateBuilder::new(&entry(
            "/tmp/a",
            "fp-1",
            stale_provenance(),
            ObjectType::File,
            Some(identity(2, 1)),
        ))
        .live_source_required(true)
        .build()
        .unwrap();

        assert_eq!(candidate.source_state, CandidateSourceState::Stale);
        assert_eq!(
            candidate.eligibility.executable,
            ExecutableEligibility::ReportOnly
        );
        assert!(
            candidate
                .eligibility
                .reasons
                .contains(&ReasonCode::NotRevalidated)
        );
    }

    #[test]
    fn same_identity_different_display_path_keeps_same_digest() {
        let entry_identity = identity(2, 1);
        let aggregate = aggregate(entry_identity.entry_id.as_str(), complete_coverage(), 3);
        let first = CandidateBuilder::new(&entry(
            "/tmp/one",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            Some(entry_identity.clone()),
        ))
        .with_aggregate(&aggregate, entry_identity.entry_id.as_str())
        .build()
        .unwrap();
        let second = CandidateBuilder::new(&entry(
            "/var/tmp/two",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            Some(entry_identity.clone()),
        ))
        .with_aggregate(&aggregate, entry_identity.entry_id.as_str())
        .build()
        .unwrap();

        assert_ne!(first.path.display_path, second.path.display_path);
        assert_eq!(first.locator, second.locator);
        assert_eq!(first.canonical_digest, second.canonical_digest);
    }

    #[test]
    fn validated_native_locator_is_carried_into_candidate_locator() {
        let entry_identity = identity(2, 1);
        let candidate = CandidateBuilder::new(&entry(
            "/tmp/file",
            "fp-1",
            live_provenance(),
            ObjectType::File,
            Some(entry_identity.clone()),
        ))
        .build()
        .unwrap();

        let locator = candidate.locator.native_locator.as_ref().unwrap();
        assert_eq!(locator.scan_root.entry_id, entry_identity.scan_root_id);
        assert_eq!(locator.entry.entry_id, entry_identity.entry_id);
        assert_eq!(
            locator
                .parent_reopen_recipe
                .last()
                .map(|component| &component.entry_id),
            entry_identity.parent_id.as_ref(),
        );
    }

    #[test]
    fn native_locator_changes_candidate_digest() {
        let entry_identity = identity(2, 1);
        let first = CandidateBuilder::new(&entry_with_native_locator(
            "/tmp/file",
            "fp-1",
            live_provenance(),
            ObjectType::File,
            Some(entry_identity.clone()),
            Some(native_locator(
                &entry_identity,
                NativeName::unix(b"demo".to_vec()),
            )),
        ))
        .build()
        .unwrap();
        let second = CandidateBuilder::new(&entry_with_native_locator(
            "/tmp/file",
            "fp-1",
            live_provenance(),
            ObjectType::File,
            Some(entry_identity.clone()),
            Some(native_locator(
                &entry_identity,
                NativeName::unix(b"different".to_vec()),
            )),
        ))
        .build()
        .unwrap();

        assert_ne!(first.locator.native_locator, second.locator.native_locator);
        assert_ne!(first.canonical_digest, second.canonical_digest);
    }

    #[test]
    fn explicit_aggregate_binding_carries_identity_and_revision() {
        let entry_identity = identity(2, 1);
        let aggregate = aggregate(entry_identity.entry_id.as_str(), complete_coverage(), 42);
        let candidate = CandidateBuilder::new(&entry(
            "/tmp/dir",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            Some(entry_identity.clone()),
        ))
        .with_aggregate(&aggregate, entry_identity.entry_id.as_str())
        .build()
        .unwrap();

        assert_eq!(
            candidate.aggregate_directory_identity.as_deref(),
            Some(entry_identity.entry_id.as_str())
        );
        assert_eq!(candidate.aggregate_revision, Some(DecimalU128::new(42)));
        assert_eq!(
            candidate.eligibility.executable,
            ExecutableEligibility::Executable
        );
    }

    #[test]
    fn missing_directory_aggregate_forces_report_only() {
        let candidate = CandidateBuilder::new(&entry(
            "/tmp/dir",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            None,
        ))
        .build()
        .unwrap();

        assert_eq!(
            candidate.eligibility.executable,
            ExecutableEligibility::ReportOnly
        );
        assert!(
            candidate
                .eligibility
                .reasons
                .contains(&ReasonCode::UnknownIdentity)
        );
    }

    #[test]
    fn supplied_identity_without_matching_aggregate_forces_report_only() {
        let candidate = CandidateBuilder::new(&entry(
            "/tmp/dir",
            "fp-1",
            live_provenance(),
            ObjectType::Directory,
            None,
        ))
        .with_expected_directory_identity("dir-identity")
        .build()
        .unwrap();

        assert_eq!(
            candidate.eligibility.executable,
            ExecutableEligibility::ReportOnly
        );
        assert!(
            candidate
                .eligibility
                .reasons
                .contains(&ReasonCode::UnknownIdentity)
        );
    }

    #[test]
    fn malformed_cross_field_identity_is_not_promoted_into_locator() {
        let mut invalid = identity(2, 1);
        invalid.parent_id = None;
        let candidate = CandidateBuilder::new(&entry(
            "/tmp/file",
            "fp-1",
            live_provenance(),
            ObjectType::File,
            Some(invalid),
        ))
        .build()
        .unwrap();

        assert_eq!(candidate.locator.scan_object_identity, None);
        assert_eq!(candidate.locator.stable_identity, None);
        assert_eq!(candidate.locator.native_locator, None);
        assert_eq!(
            candidate.eligibility.executable,
            ExecutableEligibility::ReportOnly
        );
        assert!(
            candidate
                .eligibility
                .reasons
                .contains(&ReasonCode::UnknownIdentity)
        );
    }

    #[test]
    fn malformed_native_locator_is_not_promoted_into_locator() {
        let entry_identity = identity(2, 1);
        let mut malformed = native_locator(&entry_identity, NativeName::unix(b"demo".to_vec()));
        malformed.entry.entry_id = malformed.scan_root.entry_id.clone();
        let candidate = CandidateBuilder::new(&entry_with_native_locator(
            "/tmp/file",
            "fp-1",
            live_provenance(),
            ObjectType::File,
            Some(entry_identity),
            Some(malformed),
        ))
        .build()
        .unwrap();

        assert!(candidate.locator.scan_object_identity.is_some());
        assert_eq!(candidate.locator.native_locator, None);
        assert_eq!(
            candidate.eligibility.executable,
            ExecutableEligibility::ReportOnly
        );
        assert!(
            candidate
                .eligibility
                .reasons
                .contains(&ReasonCode::UnknownIdentity)
        );
    }
}
