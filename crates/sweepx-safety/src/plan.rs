use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use sweepx_analysis::{Candidate, ExecutableEligibility};
use sweepx_model::{NativeLocatorEvidence, ScanObjectIdentity};
use thiserror::Error;

use sweepx_canonical::{
    CanonicalError, attention_fingerprint_from_digest_hex, canonical_json_bytes, plan_digest_hex,
};

const PLAN_SCHEMA: &str = "sweepx.plan/v1";
const SIMULATED_SOURCE_IDENTITY_DOMAIN: &str = "sweepx.simulated-source-identity/v1";
const SIMULATED_REVALIDATION_DOMAIN: &str = "sweepx.simulated-revalidation/v1";
pub const PLAN_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PlanId(String);

impl PlanId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ExplanationDigest(String);

impl ExplanationDigest {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ManifestDigest(String);

impl ManifestDigest {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanDigest(String);

impl PlanDigest {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn short_fingerprint(&self) -> PlanFingerprint {
        PlanFingerprint(attention_fingerprint_from_digest_hex(self.as_str()))
    }
}

impl Serialize for PlanDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanFingerprint(String);

impl PlanFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionMode {
    Trash,
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    R1,
    R2,
    R3,
    R4,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RiskFactor(String);

impl RiskFactor {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct TargetIdentity(String);

impl TargetIdentity {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativePlanTarget {
    pub(crate) scan_id: String,
    pub(crate) scan_root_identity: String,
    pub(crate) stable_identity: String,
    pub(crate) scan_object_identity: ScanObjectIdentity,
    pub(crate) native_locator: NativeLocatorEvidence,
    pub(crate) native_basename: sweepx_model::NativeName,
    pub(crate) object_type: sweepx_model::ObjectType,
    pub(crate) metadata_fingerprint: String,
    pub(crate) candidate_digest: String,
}

impl NativePlanTarget {
    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    pub fn scan_root_identity(&self) -> &str {
        &self.scan_root_identity
    }

    pub fn stable_identity(&self) -> &str {
        &self.stable_identity
    }

    pub fn scan_object_identity(&self) -> &ScanObjectIdentity {
        &self.scan_object_identity
    }

    pub fn native_locator(&self) -> &NativeLocatorEvidence {
        &self.native_locator
    }

    pub fn native_basename(&self) -> &sweepx_model::NativeName {
        &self.native_basename
    }

    pub fn object_type(&self) -> &sweepx_model::ObjectType {
        &self.object_type
    }

    pub fn metadata_fingerprint(&self) -> &str {
        &self.metadata_fingerprint
    }

    pub fn candidate_digest(&self) -> &str {
        &self.candidate_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AggregateRisk {
    pub(crate) tier: RiskTier,
    pub(crate) factors: Vec<RiskFactor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanAction {
    pub(crate) action_id: String,
    pub(crate) manifest_digest: Option<ManifestDigest>,
    pub(crate) risk_tier: RiskTier,
}

impl PlanAction {
    pub fn new(action_id: impl Into<String>, risk_tier: RiskTier) -> Self {
        Self {
            action_id: action_id.into(),
            manifest_digest: None,
            risk_tier,
        }
    }

    pub fn with_manifest_digest(mut self, digest: ManifestDigest) -> Self {
        self.manifest_digest = Some(digest);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanItem {
    pub(crate) item_id: String,
    pub(crate) candidate_id: String,
    pub(crate) explanation_digest: ExplanationDigest,
    pub(crate) top_level_action_id: String,
    pub(crate) target: TargetIdentity,
    pub(crate) native_target: Option<NativePlanTarget>,
    pub(crate) risk_tier: RiskTier,
    pub(crate) risk_factors: Vec<RiskFactor>,
    pub(crate) subtree_complete: bool,
    pub(crate) descendant_manifest_digest: Option<ManifestDigest>,
    pub(crate) actions: Vec<PlanAction>,
}

impl PlanItem {
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn action_ids(&self) -> BTreeSet<String> {
        self.actions
            .iter()
            .map(|action| action.action_id.clone())
            .collect()
    }

    pub fn digest(&self) -> Result<PlanItemDigest, CanonicalPlanError> {
        let canonical = canonical_json_bytes(self)?;
        Ok(PlanItemDigest(PlanDigest::new(
            sweepx_canonical::plan_digest_hex_from_canonical(&canonical),
        )))
    }

    pub fn native_target(&self) -> Option<&NativePlanTarget> {
        self.native_target.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItemDigest(PlanDigest);

impl PlanItemDigest {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Opaque, plan-derived input for one deterministic simulated action.
///
/// It contains stable identifiers and domain-separated digests only, never a native path or
/// mutation capability. Values can be obtained only from [`DeletionPlan::ordered_simulated_actions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedAction {
    item_id: String,
    action_id: String,
    risk_tier: RiskTier,
    source_identity_digest: String,
    revalidation_digest: String,
}

impl SimulatedAction {
    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn risk_tier(&self) -> RiskTier {
        self.risk_tier
    }

    pub fn source_identity_digest(&self) -> &str {
        &self.source_identity_digest
    }

    pub fn revalidation_digest(&self) -> &str {
        &self.revalidation_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeletionPlan {
    pub(crate) schema: String,
    pub(crate) plan_id: PlanId,
    pub(crate) nonce: String,
    pub(crate) created_at_unix_ms: u128,
    pub(crate) expires_at_unix_ms: u128,
    pub(crate) host_instance_id: String,
    pub(crate) user_identity: String,
    pub(crate) scan_id: String,
    pub(crate) scan_root_identity: String,
    pub(crate) mode: DeletionMode,
    pub(crate) candidate_version: String,
    pub(crate) scanner_version: String,
    pub(crate) safety_policy_version: String,
    pub(crate) safety_policy_digest: String,
    pub(crate) protected_anchor_snapshot_digest: String,
    pub(crate) adapter_capabilities_digest: String,
    pub(crate) cleaner_set_digest: String,
    pub(crate) items: Vec<PlanItem>,
    pub(crate) aggregate_risk: AggregateRisk,
    pub(crate) canonical_digest: PlanDigest,
}

impl DeletionPlan {
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    pub fn mode(&self) -> DeletionMode {
        self.mode
    }

    pub fn from_input(input: DeletionPlanInput) -> Result<Self, CanonicalPlanError> {
        if input.items.is_empty() {
            return Err(CanonicalPlanError::EmptyPlan);
        }

        let created_at = to_unix_millis(input.created_at)?;
        let expires_at = created_at
            .checked_add(PLAN_TTL.as_millis())
            .ok_or(CanonicalPlanError::InvalidTimestamp)?;
        let items = input
            .items
            .into_iter()
            .map(PlanItem::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        validate_plan_semantics(input.mode, &items)?;

        let aggregate_risk = aggregate_risk_for_items(&items);

        let draft = PlanDigestInput {
            schema: PLAN_SCHEMA,
            plan_id: input.plan_id.as_str(),
            nonce: &input.nonce,
            created_at_unix_ms: created_at,
            expires_at_unix_ms: expires_at,
            host_instance_id: &input.host_instance_id,
            user_identity: &input.user_identity,
            scan_id: &input.scan_id,
            scan_root_identity: &input.scan_root_identity,
            mode: input.mode,
            candidate_version: &input.candidate_version,
            scanner_version: &input.scanner_version,
            safety_policy_version: &input.safety_policy_version,
            safety_policy_digest: &input.safety_policy_digest,
            protected_anchor_snapshot_digest: &input.protected_anchor_snapshot_digest,
            adapter_capabilities_digest: &input.adapter_capabilities_digest,
            cleaner_set_digest: &input.cleaner_set_digest,
            items: &items,
            aggregate_risk: &aggregate_risk,
        };
        let canonical_digest = PlanDigest::new(plan_digest_hex(&draft)?);

        Ok(Self {
            schema: PLAN_SCHEMA.to_string(),
            plan_id: input.plan_id,
            nonce: input.nonce,
            created_at_unix_ms: created_at,
            expires_at_unix_ms: expires_at,
            host_instance_id: input.host_instance_id,
            user_identity: input.user_identity,
            scan_id: input.scan_id,
            scan_root_identity: input.scan_root_identity,
            mode: input.mode,
            candidate_version: input.candidate_version,
            scanner_version: input.scanner_version,
            safety_policy_version: input.safety_policy_version,
            safety_policy_digest: input.safety_policy_digest,
            protected_anchor_snapshot_digest: input.protected_anchor_snapshot_digest,
            adapter_capabilities_digest: input.adapter_capabilities_digest,
            cleaner_set_digest: input.cleaner_set_digest,
            items,
            aggregate_risk,
            canonical_digest,
        })
    }

    pub fn action_count(&self) -> usize {
        self.items.iter().map(PlanItem::action_count).sum()
    }

    pub fn item_ids(&self) -> BTreeSet<String> {
        self.items.iter().map(|item| item.item_id.clone()).collect()
    }

    pub fn action_ids(&self) -> BTreeSet<String> {
        self.items
            .iter()
            .flat_map(PlanItem::action_ids)
            .collect::<BTreeSet<_>>()
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        match to_unix_millis(now) {
            Ok(now_ms) => now_ms >= self.expires_at_unix_ms,
            Err(_) => true,
        }
    }

    pub(crate) fn is_created_after(&self, now: SystemTime) -> bool {
        match to_unix_millis(now) {
            Ok(now_ms) => self.created_at_unix_ms > now_ms,
            Err(_) => true,
        }
    }

    pub(crate) fn is_not_yet_valid_at(&self, now: SystemTime) -> bool {
        self.is_created_after(now)
    }

    pub fn short_fingerprint(&self) -> PlanFingerprint {
        self.canonical_digest.short_fingerprint()
    }

    pub fn canonical_digest_verified(&self) -> Result<PlanDigest, CanonicalPlanError> {
        let draft = PlanDigestInput {
            schema: &self.schema,
            plan_id: self.plan_id.as_str(),
            nonce: &self.nonce,
            created_at_unix_ms: self.created_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            host_instance_id: &self.host_instance_id,
            user_identity: &self.user_identity,
            scan_id: &self.scan_id,
            scan_root_identity: &self.scan_root_identity,
            mode: self.mode,
            candidate_version: &self.candidate_version,
            scanner_version: &self.scanner_version,
            safety_policy_version: &self.safety_policy_version,
            safety_policy_digest: &self.safety_policy_digest,
            protected_anchor_snapshot_digest: &self.protected_anchor_snapshot_digest,
            adapter_capabilities_digest: &self.adapter_capabilities_digest,
            cleaner_set_digest: &self.cleaner_set_digest,
            items: &self.items,
            aggregate_risk: &self.aggregate_risk,
        };
        Ok(PlanDigest::new(plan_digest_hex(&draft)?))
    }

    pub fn verify_canonical_digest(&self) -> Result<(), CanonicalPlanError> {
        let recomputed = self.canonical_digest_verified()?;
        if recomputed != self.canonical_digest {
            return Err(CanonicalPlanError::CanonicalDigestMismatch);
        }
        Ok(())
    }

    pub fn from_validated_json_str(json: &str) -> Result<Self, CanonicalPlanError> {
        let value: Value = serde_json::from_str(json)?;
        Self::from_validated_value(value)
    }

    pub fn from_validated_value(value: Value) -> Result<Self, CanonicalPlanError> {
        let schema = required_string(&value, "schema")?;
        if schema != PLAN_SCHEMA {
            return Err(CanonicalPlanError::InvalidField {
                field: "schema",
                reason: format!("expected {PLAN_SCHEMA}, got {schema}"),
            });
        }

        let plan = Self {
            schema,
            plan_id: PlanId::new(required_string(&value, "plan_id")?),
            nonce: required_string(&value, "nonce")?,
            created_at_unix_ms: required_u128_string(&value, "created_at_unix_ms")?,
            expires_at_unix_ms: required_u128_string(&value, "expires_at_unix_ms")?,
            host_instance_id: required_string(&value, "host_instance_id")?,
            user_identity: required_string(&value, "user_identity")?,
            scan_id: required_string(&value, "scan_id")?,
            scan_root_identity: required_string(&value, "scan_root_identity")?,
            mode: parse_mode(required_string(&value, "mode")?.as_str())?,
            candidate_version: required_string(&value, "candidate_version")?,
            scanner_version: required_string(&value, "scanner_version")?,
            safety_policy_version: required_string(&value, "safety_policy_version")?,
            safety_policy_digest: required_string(&value, "safety_policy_digest")?,
            protected_anchor_snapshot_digest: required_string(
                &value,
                "protected_anchor_snapshot_digest",
            )?,
            adapter_capabilities_digest: required_string(&value, "adapter_capabilities_digest")?,
            cleaner_set_digest: required_string(&value, "cleaner_set_digest")?,
            items: parse_items(required_array(&value, "items")?)?,
            aggregate_risk: parse_aggregate_risk(required_object_field(&value, "aggregate_risk")?)?,
            canonical_digest: PlanDigest::new(required_string(&value, "canonical_digest")?),
        };

        if plan.items.is_empty() {
            return Err(CanonicalPlanError::EmptyPlan);
        }
        validate_plan_ttl(plan.created_at_unix_ms, plan.expires_at_unix_ms)?;
        validate_plan_semantics(plan.mode, &plan.items)?;
        if plan.aggregate_risk != aggregate_risk_for_items(&plan.items) {
            return Err(CanonicalPlanError::AggregateRiskMismatch);
        }
        plan.verify_canonical_digest()?;
        Ok(plan)
    }

    pub fn selected_action_set(&self) -> SelectedActionSet {
        let manifest_digests = self
            .items
            .iter()
            .filter_map(|item| {
                item.descendant_manifest_digest
                    .as_ref()
                    .map(|digest| (item.item_id.clone(), digest.clone()))
            })
            .collect();

        SelectedActionSet {
            mode: self.mode,
            item_ids: self.item_ids(),
            action_ids: self.action_ids(),
            item_count: self.items.len(),
            action_count: self.action_count(),
            descendant_manifest_digests: manifest_digests,
        }
    }

    pub fn ordered_actions(&self) -> Vec<(String, String, RiskTier)> {
        self.items
            .iter()
            .flat_map(|item| {
                item.actions.iter().map(|action| {
                    (
                        item.item_id.clone(),
                        action.action_id.clone(),
                        action.risk_tier,
                    )
                })
            })
            .collect()
    }

    /// Derives the canonical simulated execution sequence without accepting caller-provided
    /// identity or revalidation digests.
    pub fn ordered_simulated_actions(&self) -> Result<Vec<SimulatedAction>, CanonicalPlanError> {
        self.verify_canonical_digest()?;
        validate_plan_semantics(self.mode, &self.items)?;

        self.items
            .iter()
            .flat_map(|item| {
                item.actions.iter().map(move |action| {
                    let source_identity_digest =
                        domain_separated_digest(&SimulatedSourceIdentityInput {
                            domain: SIMULATED_SOURCE_IDENTITY_DOMAIN,
                            target: &item.target,
                            native_target: item.native_target.as_ref(),
                        })?;
                    let revalidation_digest =
                        domain_separated_digest(&SimulatedRevalidationInput {
                            domain: SIMULATED_REVALIDATION_DOMAIN,
                            plan_digest: self.canonical_digest.as_str(),
                            source_identity_digest: &source_identity_digest,
                            item_id: &item.item_id,
                            action_id: &action.action_id,
                            top_level_action_id: &item.top_level_action_id,
                            action_manifest_digest: action.manifest_digest.as_ref(),
                            descendant_manifest_digest: item.descendant_manifest_digest.as_ref(),
                            risk_tier: action.risk_tier,
                            policy_version: &self.safety_policy_version,
                            policy_digest: &self.safety_policy_digest,
                            protected_anchor_snapshot_digest: &self
                                .protected_anchor_snapshot_digest,
                            adapter_capabilities_digest: &self.adapter_capabilities_digest,
                            cleaner_set_digest: &self.cleaner_set_digest,
                        })?;
                    Ok(SimulatedAction {
                        item_id: item.item_id.clone(),
                        action_id: action.action_id.clone(),
                        risk_tier: action.risk_tier,
                        source_identity_digest,
                        revalidation_digest,
                    })
                })
            })
            .collect()
    }

    pub fn exact_item(&self, item_id: &str) -> Option<&PlanItem> {
        self.items.iter().find(|item| item.item_id == item_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedActionSet {
    pub mode: DeletionMode,
    pub item_ids: BTreeSet<String>,
    pub action_ids: BTreeSet<String>,
    pub item_count: usize,
    pub action_count: usize,
    pub descendant_manifest_digests: std::collections::BTreeMap<String, ManifestDigest>,
}

#[derive(Debug, Clone)]
pub struct DeletionPlanInput {
    pub plan_id: PlanId,
    pub nonce: String,
    pub created_at: SystemTime,
    pub host_instance_id: String,
    pub user_identity: String,
    pub scan_id: String,
    pub scan_root_identity: String,
    pub mode: DeletionMode,
    pub candidate_version: String,
    pub scanner_version: String,
    pub safety_policy_version: String,
    pub safety_policy_digest: String,
    pub protected_anchor_snapshot_digest: String,
    pub adapter_capabilities_digest: String,
    pub cleaner_set_digest: String,
    pub items: Vec<PlanItemInput>,
}

#[derive(Debug, Clone)]
pub struct PlanItemInput {
    pub item_id: String,
    pub candidate_id: String,
    pub explanation_digest: ExplanationDigest,
    pub top_level_action_id: String,
    pub target: TargetIdentity,
    pub native_target: Option<NativePlanTarget>,
    pub risk_tier: RiskTier,
    pub risk_factors: Vec<RiskFactor>,
    pub subtree_complete: bool,
    pub descendant_manifest_digest: Option<ManifestDigest>,
    pub actions: Vec<PlanAction>,
}

impl TryFrom<PlanItemInput> for PlanItem {
    type Error = CanonicalPlanError;

    fn try_from(input: PlanItemInput) -> Result<Self, Self::Error> {
        if input.actions.is_empty() {
            return Err(CanonicalPlanError::ItemWithoutActions {
                item_id: input.item_id,
            });
        }
        if !input
            .actions
            .iter()
            .any(|action| action.action_id == input.top_level_action_id)
        {
            return Err(CanonicalPlanError::MissingTopLevelAction {
                item_id: input.item_id,
            });
        }
        if !input.subtree_complete {
            return Err(CanonicalPlanError::IncompleteSubtree {
                item_id: input.item_id,
            });
        }
        Ok(Self {
            item_id: input.item_id,
            candidate_id: input.candidate_id,
            explanation_digest: input.explanation_digest,
            top_level_action_id: input.top_level_action_id,
            target: input.target,
            native_target: input.native_target,
            risk_tier: input.risk_tier,
            risk_factors: input.risk_factors,
            subtree_complete: input.subtree_complete,
            descendant_manifest_digest: input.descendant_manifest_digest,
            actions: input.actions,
        })
    }
}

#[derive(Debug, Error)]
pub enum CanonicalPlanError {
    #[error("plan must contain at least one item")]
    EmptyPlan,
    #[error("item {item_id} must contain at least one action")]
    ItemWithoutActions { item_id: String },
    #[error("plan contains duplicate item id {item_id}")]
    DuplicateItemId { item_id: String },
    #[error("plan contains duplicate action id {action_id}")]
    DuplicateActionId { action_id: String },
    #[error("item {item_id} does not contain its top-level action")]
    MissingTopLevelAction { item_id: String },
    #[error("item {item_id} has incomplete subtree evidence")]
    IncompleteSubtree { item_id: String },
    #[error("permanent item {item_id} has multiple actions without a descendant manifest")]
    MissingDescendantManifest { item_id: String },
    #[error("trash item {item_id} must contain exactly its top-level action")]
    InvalidTrashActionShape { item_id: String },
    #[error("permanent item {item_id} must place its top-level action last")]
    InvalidPermanentActionOrder { item_id: String },
    #[error("trash and permanent modes cannot be mixed")]
    MixedModes,
    #[error("permanent mode requires every item and action to be R4")]
    PermanentRequiresR4,
    #[error("item {item_id} is blocked and cannot appear in a plan")]
    BlockedItemInPlan { item_id: String },
    #[error("blocked actions cannot appear in a plan")]
    BlockedActionInPlan,
    #[error(
        "item {item_id} risk {item_risk:?} is below its maximum action risk {max_action_risk:?}"
    )]
    ItemRiskBelowAction {
        item_id: String,
        item_risk: RiskTier,
        max_action_risk: RiskTier,
    },
    #[error("stored aggregate risk does not match the recomputed item risks and factors")]
    AggregateRiskMismatch,
    #[error("failed to derive canonical digest: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("failed to parse plan json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system time is outside representable unix milliseconds")]
    InvalidTimestamp,
    #[error(
        "plan expiry {expires_at_unix_ms} does not equal creation {created_at_unix_ms} plus the configured TTL"
    )]
    InvalidPlanTtl {
        created_at_unix_ms: u128,
        expires_at_unix_ms: u128,
    },
    #[error("stored canonical digest does not match the recomputed digest")]
    CanonicalDigestMismatch,
    #[error("invalid field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("item {item_id} native target binding is invalid: {reason}")]
    InvalidNativeTarget { item_id: String, reason: String },
    #[error("candidate {candidate_id} is not executable")]
    CandidateNotExecutable { candidate_id: String },
    #[error("candidate {candidate_id} is not from a current live source")]
    CandidateNotLive { candidate_id: String },
    #[error("candidate {candidate_id} is missing a validated stable identity")]
    CandidateMissingIdentity { candidate_id: String },
    #[error("candidate {candidate_id} is missing a validated native locator")]
    CandidateMissingNativeLocator { candidate_id: String },
    #[error(
        "candidate {candidate_id} scan {candidate_scan_id} does not match requested plan scan {plan_scan_id}"
    )]
    CandidateScanMismatch {
        candidate_id: String,
        candidate_scan_id: String,
        plan_scan_id: String,
    },
    #[error(
        "candidate {candidate_id} scan root {candidate_scan_root_identity} does not match requested plan root {plan_scan_root_identity}"
    )]
    CandidateScanRootMismatch {
        candidate_id: String,
        candidate_scan_root_identity: String,
        plan_scan_root_identity: String,
    },
}

#[derive(Serialize)]
struct PlanDigestInput<'a> {
    schema: &'a str,
    plan_id: &'a str,
    nonce: &'a str,
    created_at_unix_ms: u128,
    expires_at_unix_ms: u128,
    host_instance_id: &'a str,
    user_identity: &'a str,
    scan_id: &'a str,
    scan_root_identity: &'a str,
    mode: DeletionMode,
    candidate_version: &'a str,
    scanner_version: &'a str,
    safety_policy_version: &'a str,
    safety_policy_digest: &'a str,
    protected_anchor_snapshot_digest: &'a str,
    adapter_capabilities_digest: &'a str,
    cleaner_set_digest: &'a str,
    items: &'a [PlanItem],
    aggregate_risk: &'a AggregateRisk,
}

#[derive(Serialize)]
struct SimulatedSourceIdentityInput<'a> {
    domain: &'static str,
    target: &'a TargetIdentity,
    native_target: Option<&'a NativePlanTarget>,
}

#[derive(Serialize)]
struct SimulatedRevalidationInput<'a> {
    domain: &'static str,
    plan_digest: &'a str,
    source_identity_digest: &'a str,
    item_id: &'a str,
    action_id: &'a str,
    top_level_action_id: &'a str,
    action_manifest_digest: Option<&'a ManifestDigest>,
    descendant_manifest_digest: Option<&'a ManifestDigest>,
    risk_tier: RiskTier,
    policy_version: &'a str,
    policy_digest: &'a str,
    protected_anchor_snapshot_digest: &'a str,
    adapter_capabilities_digest: &'a str,
    cleaner_set_digest: &'a str,
}

fn domain_separated_digest<T: Serialize>(value: &T) -> Result<String, CanonicalPlanError> {
    Ok(format!("sha256:{}", plan_digest_hex(value)?))
}

fn required_string(root: &Value, field: &'static str) -> Result<String, CanonicalPlanError> {
    root.get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| CanonicalPlanError::InvalidField {
            field,
            reason: "expected string".to_string(),
        })
}

fn required_u128_string(root: &Value, field: &'static str) -> Result<u128, CanonicalPlanError> {
    match root.get(field) {
        Some(Value::String(raw)) => {
            raw.parse::<u128>()
                .map_err(|_| CanonicalPlanError::InvalidField {
                    field,
                    reason: "expected decimal u128 string".to_string(),
                })
        }
        Some(Value::Number(raw)) => {
            raw.as_u64()
                .map(u128::from)
                .ok_or_else(|| CanonicalPlanError::InvalidField {
                    field,
                    reason: "expected non-negative integer".to_string(),
                })
        }
        _ => Err(CanonicalPlanError::InvalidField {
            field,
            reason: "expected decimal string or integer".to_string(),
        }),
    }
}

fn required_array<'a>(
    root: &'a Value,
    field: &'static str,
) -> Result<&'a [Value], CanonicalPlanError> {
    root.get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| CanonicalPlanError::InvalidField {
            field,
            reason: "expected array".to_string(),
        })
}

fn required_object_field<'a>(
    root: &'a Value,
    field: &'static str,
) -> Result<&'a Value, CanonicalPlanError> {
    root.get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| CanonicalPlanError::InvalidField {
            field,
            reason: "expected object".to_string(),
        })
}

fn parse_mode(raw: &str) -> Result<DeletionMode, CanonicalPlanError> {
    match raw {
        "trash" => Ok(DeletionMode::Trash),
        "permanent" => Ok(DeletionMode::Permanent),
        _ => Err(CanonicalPlanError::InvalidField {
            field: "mode",
            reason: format!("unknown mode {raw}"),
        }),
    }
}

fn parse_risk_tier(field: &'static str, raw: &str) -> Result<RiskTier, CanonicalPlanError> {
    match raw {
        "r1" => Ok(RiskTier::R1),
        "r2" => Ok(RiskTier::R2),
        "r3" => Ok(RiskTier::R3),
        "r4" => Ok(RiskTier::R4),
        "blocked" => Ok(RiskTier::Blocked),
        _ => Err(CanonicalPlanError::InvalidField {
            field,
            reason: format!("unknown risk tier {raw}"),
        }),
    }
}

fn parse_aggregate_risk(value: &Value) -> Result<AggregateRisk, CanonicalPlanError> {
    let tier = parse_risk_tier("aggregate_risk.tier", &required_string(value, "tier")?)?;
    let factors = required_array(value, "factors")?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(RiskFactor::new)
                .ok_or_else(|| CanonicalPlanError::InvalidField {
                    field: "aggregate_risk.factors",
                    reason: "expected string entries".to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AggregateRisk { tier, factors })
}

fn parse_items(entries: &[Value]) -> Result<Vec<PlanItem>, CanonicalPlanError> {
    entries.iter().map(parse_item).collect()
}

fn parse_item(value: &Value) -> Result<PlanItem, CanonicalPlanError> {
    let actions = required_array(value, "actions")?
        .iter()
        .map(parse_action)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PlanItem {
        item_id: required_string(value, "item_id")?,
        candidate_id: required_string(value, "candidate_id")?,
        explanation_digest: ExplanationDigest::new(required_string(value, "explanation_digest")?),
        top_level_action_id: required_string(value, "top_level_action_id")?,
        target: TargetIdentity::new(required_string(value, "target")?),
        native_target: optional_native_target(value)?,
        risk_tier: parse_risk_tier("risk_tier", &required_string(value, "risk_tier")?)?,
        risk_factors: required_array(value, "risk_factors")?
            .iter()
            .map(|entry| {
                entry.as_str().map(RiskFactor::new).ok_or_else(|| {
                    CanonicalPlanError::InvalidField {
                        field: "risk_factors",
                        reason: "expected string entries".to_string(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        subtree_complete: value
            .get("subtree_complete")
            .and_then(Value::as_bool)
            .ok_or_else(|| CanonicalPlanError::InvalidField {
                field: "subtree_complete",
                reason: "expected bool".to_string(),
            })?,
        descendant_manifest_digest: optional_manifest_digest(value, "descendant_manifest_digest")?,
        actions,
    })
}

fn parse_action(value: &Value) -> Result<PlanAction, CanonicalPlanError> {
    Ok(PlanAction {
        action_id: required_string(value, "action_id")?,
        manifest_digest: optional_manifest_digest(value, "manifest_digest")?,
        risk_tier: parse_risk_tier("risk_tier", &required_string(value, "risk_tier")?)?,
    })
}

fn optional_manifest_digest(
    root: &Value,
    field: &'static str,
) -> Result<Option<ManifestDigest>, CanonicalPlanError> {
    match root.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => Ok(Some(ManifestDigest::new(raw))),
        Some(_) => Err(CanonicalPlanError::InvalidField {
            field,
            reason: "expected string or null".to_string(),
        }),
    }
}

fn optional_native_target(root: &Value) -> Result<Option<NativePlanTarget>, CanonicalPlanError> {
    let Some(value) = root.get("native_target") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(parse_native_target(value)?))
}

fn parse_native_target(value: &Value) -> Result<NativePlanTarget, CanonicalPlanError> {
    Ok(NativePlanTarget {
        scan_id: required_string(value, "scan_id")?,
        scan_root_identity: required_string(value, "scan_root_identity")?,
        stable_identity: required_string(value, "stable_identity")?,
        scan_object_identity: serde_json::from_value(
            value.get("scan_object_identity").cloned().ok_or_else(|| {
                CanonicalPlanError::InvalidField {
                    field: "native_target.scan_object_identity",
                    reason: "expected object".to_string(),
                }
            })?,
        )
        .map_err(CanonicalPlanError::Json)?,
        native_locator: serde_json::from_value(value.get("native_locator").cloned().ok_or_else(
            || CanonicalPlanError::InvalidField {
                field: "native_target.native_locator",
                reason: "expected object".to_string(),
            },
        )?)
        .map_err(CanonicalPlanError::Json)?,
        native_basename: serde_json::from_value(value.get("native_basename").cloned().ok_or_else(
            || CanonicalPlanError::InvalidField {
                field: "native_target.native_basename",
                reason: "expected object".to_string(),
            },
        )?)
        .map_err(CanonicalPlanError::Json)?,
        object_type: serde_json::from_value(value.get("object_type").cloned().ok_or_else(
            || CanonicalPlanError::InvalidField {
                field: "native_target.object_type",
                reason: "expected object type".to_string(),
            },
        )?)
        .map_err(CanonicalPlanError::Json)?,
        metadata_fingerprint: required_string(value, "metadata_fingerprint")?,
        candidate_digest: required_string(value, "candidate_digest")?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_item_from_live_candidate(
    scan_id: &str,
    scan_root_identity: &str,
    candidate: &Candidate,
    explanation_digest: ExplanationDigest,
    top_level_action_id: impl Into<String>,
    target: TargetIdentity,
    actions: Vec<PlanAction>,
    descendant_manifest_digest: Option<ManifestDigest>,
) -> Result<PlanItemInput, CanonicalPlanError> {
    let candidate_id = candidate.candidate_id.to_string();
    if candidate.eligibility.executable != ExecutableEligibility::Executable {
        return Err(CanonicalPlanError::CandidateNotExecutable { candidate_id });
    }
    if !candidate.source_state.is_live() || !candidate.source_state.is_current() {
        return Err(CanonicalPlanError::CandidateNotLive { candidate_id });
    }
    if candidate.scan_id.to_string() != scan_id {
        return Err(CanonicalPlanError::CandidateScanMismatch {
            candidate_id,
            candidate_scan_id: candidate.scan_id.to_string(),
            plan_scan_id: scan_id.to_string(),
        });
    }

    let stable_identity = candidate.locator.stable_identity.clone().ok_or_else(|| {
        CanonicalPlanError::CandidateMissingIdentity {
            candidate_id: candidate.candidate_id.to_string(),
        }
    })?;
    let scan_object_identity = candidate
        .locator
        .scan_object_identity
        .clone()
        .ok_or_else(|| CanonicalPlanError::CandidateMissingIdentity {
            candidate_id: candidate.candidate_id.to_string(),
        })?;
    if scan_object_identity.scan_root_id.as_str() != scan_root_identity {
        return Err(CanonicalPlanError::CandidateScanRootMismatch {
            candidate_id: candidate.candidate_id.to_string(),
            candidate_scan_root_identity: scan_object_identity.scan_root_id.to_string(),
            plan_scan_root_identity: scan_root_identity.to_string(),
        });
    }
    let native_locator = candidate.locator.native_locator.clone().ok_or_else(|| {
        CanonicalPlanError::CandidateMissingNativeLocator {
            candidate_id: candidate.candidate_id.to_string(),
        }
    })?;

    Ok(PlanItemInput {
        item_id: format!("item-{}", candidate.candidate_id),
        candidate_id: candidate.candidate_id.to_string(),
        explanation_digest,
        top_level_action_id: top_level_action_id.into(),
        target,
        native_target: Some(NativePlanTarget {
            scan_id: candidate.scan_id.to_string(),
            scan_root_identity: scan_root_identity.to_string(),
            stable_identity,
            scan_object_identity,
            native_locator,
            native_basename: candidate.locator.native_basename.clone(),
            object_type: candidate.object_type.clone(),
            metadata_fingerprint: candidate.metadata_fingerprint.clone(),
            candidate_digest: candidate.canonical_digest.clone(),
        }),
        risk_tier: match candidate.risk.tier {
            sweepx_model::RiskTier::R1 => RiskTier::R1,
            sweepx_model::RiskTier::R2 => RiskTier::R2,
            sweepx_model::RiskTier::R3 => RiskTier::R3,
            sweepx_model::RiskTier::R4 => RiskTier::R4,
            sweepx_model::RiskTier::Blocked => RiskTier::Blocked,
        },
        risk_factors: candidate
            .risk
            .signals
            .iter()
            .map(|signal| RiskFactor::new(format!("{signal:?}")))
            .collect(),
        subtree_complete: candidate.coverage.complete
            && candidate
                .aggregate_coverage
                .as_ref()
                .is_none_or(|coverage| coverage.complete),
        descendant_manifest_digest,
        actions,
    })
}

fn validate_plan_ttl(
    created_at_unix_ms: u128,
    expires_at_unix_ms: u128,
) -> Result<(), CanonicalPlanError> {
    let expected_expires_at = created_at_unix_ms.checked_add(PLAN_TTL.as_millis());
    if expected_expires_at != Some(expires_at_unix_ms) {
        return Err(CanonicalPlanError::InvalidPlanTtl {
            created_at_unix_ms,
            expires_at_unix_ms,
        });
    }
    Ok(())
}

fn aggregate_risk_for_items(items: &[PlanItem]) -> AggregateRisk {
    AggregateRisk {
        tier: items
            .iter()
            .map(|item| item.risk_tier)
            .max()
            .expect("validated non-empty items"),
        factors: items
            .iter()
            .flat_map(|item| item.risk_factors.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

fn validate_plan_semantics(
    mode: DeletionMode,
    items: &[PlanItem],
) -> Result<(), CanonicalPlanError> {
    let mut item_ids = BTreeSet::new();
    let mut action_ids = BTreeSet::new();

    for item in items {
        if !item_ids.insert(item.item_id.as_str()) {
            return Err(CanonicalPlanError::DuplicateItemId {
                item_id: item.item_id.clone(),
            });
        }
        for action in &item.actions {
            if !action_ids.insert(action.action_id.as_str()) {
                return Err(CanonicalPlanError::DuplicateActionId {
                    action_id: action.action_id.clone(),
                });
            }
        }
    }

    for item in items {
        if item.actions.is_empty() {
            return Err(CanonicalPlanError::ItemWithoutActions {
                item_id: item.item_id.clone(),
            });
        }
        if item.risk_tier == RiskTier::Blocked {
            return Err(CanonicalPlanError::BlockedItemInPlan {
                item_id: item.item_id.clone(),
            });
        }
        if item
            .actions
            .iter()
            .any(|action| action.risk_tier == RiskTier::Blocked)
        {
            return Err(CanonicalPlanError::BlockedActionInPlan);
        }
        let max_action_risk = item
            .actions
            .iter()
            .map(|action| action.risk_tier)
            .max()
            .expect("validated non-empty actions");
        if item.risk_tier < max_action_risk {
            return Err(CanonicalPlanError::ItemRiskBelowAction {
                item_id: item.item_id.clone(),
                item_risk: item.risk_tier,
                max_action_risk,
            });
        }
        if let Some(native_target) = &item.native_target {
            validate_native_target(&item.item_id, native_target)?;
        }
        if mode == DeletionMode::Permanent
            && (item.risk_tier != RiskTier::R4
                || item
                    .actions
                    .iter()
                    .any(|action| action.risk_tier != RiskTier::R4))
        {
            return Err(CanonicalPlanError::PermanentRequiresR4);
        }
        if !item.subtree_complete {
            return Err(CanonicalPlanError::IncompleteSubtree {
                item_id: item.item_id.clone(),
            });
        }
        let top_level_position = item
            .actions
            .iter()
            .position(|action| action.action_id == item.top_level_action_id)
            .ok_or_else(|| CanonicalPlanError::MissingTopLevelAction {
                item_id: item.item_id.clone(),
            })?;
        match mode {
            DeletionMode::Trash if item.actions.len() != 1 || top_level_position != 0 => {
                return Err(CanonicalPlanError::InvalidTrashActionShape {
                    item_id: item.item_id.clone(),
                });
            }
            DeletionMode::Permanent if top_level_position + 1 != item.actions.len() => {
                return Err(CanonicalPlanError::InvalidPermanentActionOrder {
                    item_id: item.item_id.clone(),
                });
            }
            DeletionMode::Permanent
                if item.actions.len() > 1 && item.descendant_manifest_digest.is_none() =>
            {
                return Err(CanonicalPlanError::MissingDescendantManifest {
                    item_id: item.item_id.clone(),
                });
            }
            _ => {}
        }
    }

    Ok(())
}

fn validate_native_target(
    item_id: &str,
    native_target: &NativePlanTarget,
) -> Result<(), CanonicalPlanError> {
    if native_target.scan_id.is_empty() {
        return Err(invalid_native_target(item_id, "scan_id is empty"));
    }
    if native_target.scan_root_identity.is_empty() {
        return Err(invalid_native_target(
            item_id,
            "scan_root_identity is empty",
        ));
    }
    if native_target.stable_identity.is_empty() {
        return Err(invalid_native_target(item_id, "stable_identity is empty"));
    }
    if native_target.candidate_digest.is_empty() {
        return Err(invalid_native_target(item_id, "candidate_digest is empty"));
    }
    if native_target.metadata_fingerprint.is_empty() {
        return Err(invalid_native_target(
            item_id,
            "metadata_fingerprint is empty",
        ));
    }
    if native_target.stable_identity != native_target.scan_object_identity.entry_id.as_str() {
        return Err(invalid_native_target(
            item_id,
            "stable_identity does not match scan_object_identity.entry_id",
        ));
    }
    if native_target.scan_root_identity != native_target.scan_object_identity.scan_root_id.as_str()
    {
        return Err(invalid_native_target(
            item_id,
            "scan_root_identity does not match scan_object_identity.scan_root_id",
        ));
    }
    if native_target
        .scan_object_identity
        .validate_for_scan(&sweepx_model::ScanId::new(native_target.scan_id.clone()))
        .is_err()
    {
        return Err(invalid_native_target(
            item_id,
            "scan_object_identity is not valid for scan_id",
        ));
    }
    if native_target
        .native_locator
        .validate_for_identity(
            &native_target.scan_object_identity,
            &sweepx_model::ScanId::new(native_target.scan_id.clone()),
        )
        .is_err()
    {
        return Err(invalid_native_target(
            item_id,
            "native_locator does not match scan_object_identity",
        ));
    }
    if native_target
        .native_locator
        .scan_root_absolute_path
        .as_ref()
        .is_none_or(|path| path.validate_for_current_platform().is_err())
    {
        return Err(invalid_native_target(
            item_id,
            "native_locator has no valid current-platform scan root absolute path",
        ));
    }
    if native_target.native_locator.entry.native_basename != native_target.native_basename {
        return Err(invalid_native_target(
            item_id,
            "native basename does not match locator entry",
        ));
    }
    Ok(())
}

fn invalid_native_target(item_id: &str, reason: &'static str) -> CanonicalPlanError {
    CanonicalPlanError::InvalidNativeTarget {
        item_id: item_id.to_string(),
        reason: reason.to_string(),
    }
}

fn to_unix_millis(value: SystemTime) -> Result<u128, CanonicalPlanError> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| CanonicalPlanError::InvalidTimestamp)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sweepx_analysis::{
        Candidate as AnalysisCandidate, CandidateEligibility, CandidateLocator,
        CandidateSourceState, PathPresentation, RiskAssessment, RiskSignal,
    };
    use sweepx_model::{
        CandidateId, Coverage, CoverageState, DecimalU128, EvidenceValue, FieldProvenance,
        MethodId, NativeAbsolutePath, NativeLocatorEvidence, NativeName, NativePathComponent,
        ObjectType, ScanEntryId, ScanId, ScanObjectIdentity,
    };

    use super::*;

    fn base_input() -> DeletionPlanInput {
        DeletionPlanInput {
            plan_id: PlanId::new("plan-1"),
            nonce: "nonce-1".to_string(),
            created_at: UNIX_EPOCH + Duration::from_secs(100),
            host_instance_id: "host-1".to_string(),
            user_identity: "user-1".to_string(),
            scan_id: "scan-1".to_string(),
            scan_root_identity: "root-1".to_string(),
            mode: DeletionMode::Trash,
            candidate_version: "candidate-v1".to_string(),
            scanner_version: "scanner-v1".to_string(),
            safety_policy_version: "policy-v1".to_string(),
            safety_policy_digest: "policy-digest".to_string(),
            protected_anchor_snapshot_digest: "anchors-digest".to_string(),
            adapter_capabilities_digest: "adapter-digest".to_string(),
            cleaner_set_digest: "cleaner-digest".to_string(),
            items: vec![PlanItemInput {
                item_id: "item-1".to_string(),
                candidate_id: "candidate-1".to_string(),
                explanation_digest: ExplanationDigest::new("explain-1"),
                top_level_action_id: "action-top-1".to_string(),
                target: TargetIdentity::new("target-1"),
                native_target: None,
                risk_tier: RiskTier::R2,
                risk_factors: vec![RiskFactor::new("user-content")],
                subtree_complete: true,
                descendant_manifest_digest: Some(ManifestDigest::new("manifest-1")),
                actions: vec![
                    PlanAction::new("action-top-1", RiskTier::R2)
                        .with_manifest_digest(ManifestDigest::new("manifest-1")),
                ],
            }],
        }
    }

    fn additional_trash_item(item_id: &str, action_id: &str) -> PlanItemInput {
        let mut input = base_input();
        let mut item = input.items.pop().unwrap();
        item.item_id = item_id.to_string();
        item.candidate_id = format!("candidate-{item_id}");
        item.explanation_digest = ExplanationDigest::new(format!("explain-{item_id}"));
        item.top_level_action_id = action_id.to_string();
        item.target = TargetIdentity::new(format!("target-{item_id}"));
        item.actions = vec![PlanAction::new(action_id, RiskTier::R2)];
        item
    }

    fn permanent_multi_action_input() -> DeletionPlanInput {
        let mut input = base_input();
        input.mode = DeletionMode::Permanent;
        input.items[0].risk_tier = RiskTier::R4;
        input.items[0].descendant_manifest_digest =
            Some(ManifestDigest::new("descendant-manifest-1"));
        input.items[0].actions = vec![
            PlanAction::new("action-child-1", RiskTier::R4),
            PlanAction::new("action-top-1", RiskTier::R4),
        ];
        input
    }

    fn native_absolute_root() -> NativeAbsolutePath {
        #[cfg(unix)]
        {
            NativeAbsolutePath::unix(b"/tmp/root".to_vec())
        }
        #[cfg(windows)]
        {
            NativeAbsolutePath::windows_utf16(r"C:\root".encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeAbsolutePath::unix(b"/tmp/root".to_vec())
        }
    }

    fn live_candidate() -> AnalysisCandidate {
        let scan_id = ScanId::new("scan-1");
        let root_id = ScanEntryId::for_scan_ordinal(&scan_id, 1).unwrap();
        let entry_id = ScanEntryId::for_scan_ordinal(&scan_id, 2).unwrap();
        let scan_object_identity = ScanObjectIdentity {
            entry_id: entry_id.clone(),
            scan_root_id: root_id.clone(),
            parent_id: Some(root_id.clone()),
            platform_file_identity: sweepx_model::IdentityEvidence::known(
                sweepx_model::PlatformFileIdentity {
                    device: DecimalU128::new(1),
                    inode: DecimalU128::new(2),
                },
            ),
            filesystem_object_domain_identity: sweepx_model::IdentityEvidence::known(
                sweepx_model::FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: sweepx_model::IdentityEvidence::known(
                sweepx_model::VolumeOrMountIdentity {
                    value: DecimalU128::new(1),
                },
            ),
        };
        AnalysisCandidate {
            candidate_id: CandidateId::new("cand-live"),
            canonical_digest: "sha256:candidate-live".to_string(),
            scan_id: scan_id.clone(),
            object_type: ObjectType::File,
            metadata_fingerprint: "fp-live".to_string(),
            path: PathPresentation {
                display_path: "/tmp/live".to_string(),
                native_basename: NativeName::unix(b"live".to_vec()),
                stable_identity: Some(entry_id.to_string()),
            },
            locator: CandidateLocator {
                stable_identity: Some(entry_id.to_string()),
                scan_object_identity: Some(scan_object_identity.clone()),
                native_locator: Some(NativeLocatorEvidence {
                    scan_root: NativePathComponent {
                        entry_id: root_id.clone(),
                        native_basename: NativeName::unix(b"root".to_vec()),
                        object_type: ObjectType::Directory,
                        platform_file_identity: scan_object_identity.platform_file_identity.clone(),
                        filesystem_object_domain_identity: scan_object_identity
                            .filesystem_object_domain_identity
                            .clone(),
                        volume_or_mount_identity: scan_object_identity
                            .volume_or_mount_identity
                            .clone(),
                        metadata_fingerprint: "fp-root".to_string(),
                    },
                    scan_root_absolute_path: Some(native_absolute_root()),
                    parent_reopen_recipe: vec![NativePathComponent {
                        entry_id: root_id.clone(),
                        native_basename: NativeName::unix(b"root".to_vec()),
                        object_type: ObjectType::Directory,
                        platform_file_identity: scan_object_identity.platform_file_identity.clone(),
                        filesystem_object_domain_identity: scan_object_identity
                            .filesystem_object_domain_identity
                            .clone(),
                        volume_or_mount_identity: scan_object_identity
                            .volume_or_mount_identity
                            .clone(),
                        metadata_fingerprint: "fp-root".to_string(),
                    }],
                    entry: NativePathComponent {
                        entry_id: entry_id.clone(),
                        native_basename: NativeName::unix(b"live".to_vec()),
                        object_type: ObjectType::File,
                        platform_file_identity: scan_object_identity.platform_file_identity.clone(),
                        filesystem_object_domain_identity: scan_object_identity
                            .filesystem_object_domain_identity
                            .clone(),
                        volume_or_mount_identity: scan_object_identity
                            .volume_or_mount_identity
                            .clone(),
                        metadata_fingerprint: "fp-live".to_string(),
                    },
                }),
                native_basename: NativeName::unix(b"live".to_vec()),
                metadata_fingerprint: "fp-live".to_string(),
            },
            provenance: FieldProvenance::LiveObservation {
                observed_at: "2026-08-27T00:00:00Z".to_string(),
                method: MethodId::NativeApi,
            },
            source_state: CandidateSourceState::Live,
            live_source_required: true,
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            coverage: Coverage {
                state: CoverageState::Complete,
                complete: true,
                incomplete_reasons: Vec::new(),
                details_lost: false,
                provenance: FieldProvenance::LiveObservation {
                    observed_at: "2026-08-27T00:00:00Z".to_string(),
                    method: MethodId::NativeApi,
                },
            },
            aggregate_directory_identity: None,
            aggregate_revision: None,
            aggregate_coverage: None,
            aggregate_arithmetic_state: None,
            risk: RiskAssessment {
                tier: sweepx_model::RiskTier::R2,
                signals: vec![RiskSignal::Fact {
                    code: "live".to_string(),
                }],
            },
            eligibility: CandidateEligibility {
                executable: sweepx_analysis::ExecutableEligibility::Executable,
                reasons: Vec::new(),
            },
        }
    }

    #[test]
    fn plan_edit_changes_digest() {
        let left = DeletionPlan::from_input(base_input()).unwrap();
        let mut edited = base_input();
        edited.items[0]
            .risk_factors
            .push(RiskFactor::new("recently-modified"));
        let right = DeletionPlan::from_input(edited).unwrap();

        assert_ne!(
            left.canonical_digest.as_str(),
            right.canonical_digest.as_str()
        );
    }

    #[test]
    fn permanent_plan_requires_r4() {
        let mut input = base_input();
        input.mode = DeletionMode::Permanent;

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(error, CanonicalPlanError::PermanentRequiresR4));
    }

    #[test]
    fn permanent_plan_accepts_r4_only() {
        let mut input = base_input();
        input.mode = DeletionMode::Permanent;
        input.items[0].risk_tier = RiskTier::R4;
        input.items[0].actions[0].risk_tier = RiskTier::R4;

        let plan = DeletionPlan::from_input(input).unwrap();
        assert_eq!(plan.aggregate_risk.tier, RiskTier::R4);
        assert_eq!(plan.mode, DeletionMode::Permanent);
    }

    #[test]
    fn rejects_duplicate_item_ids() {
        let mut input = base_input();
        input
            .items
            .push(additional_trash_item("item-1", "action-top-2"));

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::DuplicateItemId { ref item_id } if item_id == "item-1"
        ));
    }

    #[test]
    fn rejects_duplicate_action_ids_across_items() {
        let mut input = base_input();
        input
            .items
            .push(additional_trash_item("item-2", "action-top-1"));

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::DuplicateActionId { ref action_id }
                if action_id == "action-top-1"
        ));
    }

    #[test]
    fn rejects_duplicate_action_ids_within_an_item() {
        let mut input = base_input();
        input.items[0]
            .actions
            .push(PlanAction::new("action-top-1", RiskTier::R2));

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::DuplicateActionId { ref action_id }
                if action_id == "action-top-1"
        ));
    }

    #[test]
    fn rejects_top_level_action_owned_by_another_item() {
        let mut input = base_input();
        input.items[0].top_level_action_id = "action-top-2".to_string();
        input
            .items
            .push(additional_trash_item("item-2", "action-top-2"));

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::MissingTopLevelAction { ref item_id } if item_id == "item-1"
        ));
    }

    #[test]
    fn rejects_incomplete_subtree_from_input() {
        let mut input = base_input();
        input.items[0].subtree_complete = false;

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::IncompleteSubtree { ref item_id } if item_id == "item-1"
        ));
    }

    #[test]
    fn trash_rejects_extra_action() {
        let mut input = base_input();
        input.items[0]
            .actions
            .insert(0, PlanAction::new("action-child-1", RiskTier::R2));

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::InvalidTrashActionShape { ref item_id } if item_id == "item-1"
        ));
    }

    #[test]
    fn permanent_rejects_top_level_action_before_descendants() {
        let mut input = permanent_multi_action_input();
        input.items[0].actions.swap(0, 1);

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::InvalidPermanentActionOrder { ref item_id }
                if item_id == "item-1"
        ));
    }

    #[test]
    fn permanent_preserves_descendant_then_top_level_order() {
        let plan = DeletionPlan::from_input(permanent_multi_action_input()).unwrap();
        let action_ids = plan.items[0]
            .actions
            .iter()
            .map(|action| action.action_id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(action_ids, vec!["action-child-1", "action-top-1"]);
    }

    #[test]
    fn simulated_action_source_identity_is_stable_across_plan_and_logical_ids() {
        let first = DeletionPlan::from_input(base_input()).unwrap();
        let mut changed = base_input();
        changed.plan_id = PlanId::new("different-plan-id");
        changed.nonce = "different-plan-nonce".to_string();
        changed.items[0].item_id = "different-item-id".to_string();
        changed.items[0].candidate_id = "different-candidate-id".to_string();
        changed.items[0].top_level_action_id = "different-action-id".to_string();
        changed.items[0].actions[0] = PlanAction::new("different-action-id", RiskTier::R2);
        let second = DeletionPlan::from_input(changed).unwrap();

        let first = first.ordered_simulated_actions().unwrap();
        let second = second.ordered_simulated_actions().unwrap();
        assert_eq!(
            first[0].source_identity_digest(),
            second[0].source_identity_digest()
        );
        assert_ne!(
            first[0].revalidation_digest(),
            second[0].revalidation_digest()
        );
    }

    #[test]
    fn simulated_action_source_identity_distinguishes_target_but_not_logical_action_id() {
        let original = DeletionPlan::from_input(base_input())
            .unwrap()
            .ordered_simulated_actions()
            .unwrap();
        let mut changed_target = base_input();
        changed_target.items[0].target = TargetIdentity::new("different-target");
        let changed_target = DeletionPlan::from_input(changed_target)
            .unwrap()
            .ordered_simulated_actions()
            .unwrap();
        let mut changed_action = base_input();
        changed_action.items[0].top_level_action_id = "different-action".to_string();
        changed_action.items[0].actions[0] = PlanAction::new("different-action", RiskTier::R2);
        let changed_action = DeletionPlan::from_input(changed_action)
            .unwrap()
            .ordered_simulated_actions()
            .unwrap();

        assert_ne!(
            original[0].source_identity_digest(),
            changed_target[0].source_identity_digest()
        );
        assert_eq!(
            original[0].source_identity_digest(),
            changed_action[0].source_identity_digest()
        );
        assert_ne!(
            original[0].revalidation_digest(),
            changed_action[0].revalidation_digest()
        );
        assert_eq!(original[0].item_id(), "item-1");
        assert_eq!(original[0].action_id(), "action-top-1");
        assert_eq!(original[0].risk_tier(), RiskTier::R2);
    }

    #[test]
    fn live_candidate_builder_attaches_native_target() {
        let candidate = live_candidate();
        let item = plan_item_from_live_candidate(
            "scan-1",
            candidate
                .locator
                .scan_object_identity
                .as_ref()
                .unwrap()
                .scan_root_id
                .as_str(),
            &candidate,
            ExplanationDigest::new("explain-live"),
            "action-live",
            TargetIdentity::new("target-live"),
            vec![PlanAction::new("action-live", RiskTier::R2)],
            None,
        )
        .unwrap();

        let native_target = item.native_target.as_ref().unwrap();
        assert_eq!(native_target.candidate_digest, candidate.canonical_digest);
        assert_eq!(
            native_target.stable_identity,
            candidate.locator.stable_identity.clone().unwrap()
        );
        assert_eq!(
            native_target.native_locator,
            candidate.locator.native_locator.clone().unwrap()
        );
    }

    #[test]
    fn live_candidate_builder_rejects_missing_native_locator() {
        let mut candidate = live_candidate();
        candidate.locator.native_locator = None;

        let error = plan_item_from_live_candidate(
            "scan-1",
            candidate
                .locator
                .scan_object_identity
                .as_ref()
                .unwrap()
                .scan_root_id
                .as_str(),
            &candidate,
            ExplanationDigest::new("explain-live"),
            "action-live",
            TargetIdentity::new("target-live"),
            vec![PlanAction::new("action-live", RiskTier::R2)],
            None,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CanonicalPlanError::CandidateMissingNativeLocator { .. }
        ));
    }

    #[test]
    fn native_target_rejects_missing_absolute_root_locator() {
        let candidate = live_candidate();
        let mut item = plan_item_from_live_candidate(
            "scan-1",
            candidate
                .locator
                .scan_object_identity
                .as_ref()
                .unwrap()
                .scan_root_id
                .as_str(),
            &candidate,
            ExplanationDigest::new("explain-1"),
            "action-top-1",
            TargetIdentity::new("target-1"),
            vec![PlanAction::new("action-top-1", RiskTier::R2)],
            None,
        )
        .unwrap();
        item.native_target
            .as_mut()
            .unwrap()
            .native_locator
            .scan_root_absolute_path = None;

        assert!(matches!(
            validate_native_target("item-1", item.native_target.as_ref().unwrap()),
            Err(CanonicalPlanError::InvalidNativeTarget { .. })
        ));
    }

    #[test]
    fn plan_item_digest_changes_when_native_target_changes() {
        let first = PlanItem::try_from(
            plan_item_from_live_candidate(
                "scan-1",
                live_candidate()
                    .locator
                    .scan_object_identity
                    .as_ref()
                    .unwrap()
                    .scan_root_id
                    .as_str(),
                &live_candidate(),
                ExplanationDigest::new("explain-live"),
                "action-live",
                TargetIdentity::new("target-live"),
                vec![PlanAction::new("action-live", RiskTier::R2)],
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let mut changed_candidate = live_candidate();
        changed_candidate
            .locator
            .native_locator
            .as_mut()
            .unwrap()
            .entry
            .native_basename = NativeName::unix(b"changed".to_vec());
        let second = PlanItem::try_from(
            plan_item_from_live_candidate(
                "scan-1",
                changed_candidate
                    .locator
                    .scan_object_identity
                    .as_ref()
                    .unwrap()
                    .scan_root_id
                    .as_str(),
                &changed_candidate,
                ExplanationDigest::new("explain-live"),
                "action-live",
                TargetIdentity::new("target-live"),
                vec![PlanAction::new("action-live", RiskTier::R2)],
                None,
            )
            .unwrap(),
        )
        .unwrap();

        assert_ne!(first.native_target(), second.native_target());
        assert_ne!(
            first.digest().unwrap().as_str(),
            second.digest().unwrap().as_str()
        );
    }

    #[test]
    fn permanent_multi_action_rejects_missing_descendant_manifest() {
        let mut input = permanent_multi_action_input();
        input.items[0].descendant_manifest_digest = None;

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::MissingDescendantManifest { ref item_id }
                if item_id == "item-1"
        ));
    }

    #[test]
    fn rejects_blocked_item_even_when_its_action_is_r1() {
        let mut input = base_input();
        input.items[0].risk_tier = RiskTier::Blocked;
        input.items[0].actions[0].risk_tier = RiskTier::R1;

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::BlockedItemInPlan { ref item_id } if item_id == "item-1"
        ));
    }

    #[test]
    fn rejects_item_risk_below_action_risk() {
        let mut input = base_input();
        input.items[0].risk_tier = RiskTier::R1;
        input.items[0].actions[0].risk_tier = RiskTier::R3;

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::ItemRiskBelowAction {
                ref item_id,
                item_risk: RiskTier::R1,
                max_action_risk: RiskTier::R3,
            } if item_id == "item-1"
        ));
    }

    #[test]
    fn permanent_rejects_non_r4_action_even_when_item_is_r4() {
        let mut input = base_input();
        input.mode = DeletionMode::Permanent;
        input.items[0].risk_tier = RiskTier::R4;
        input.items[0].actions[0].risk_tier = RiskTier::R3;

        let error = DeletionPlan::from_input(input).unwrap_err();
        assert!(matches!(error, CanonicalPlanError::PermanentRequiresR4));
    }

    #[test]
    fn short_fingerprint_is_not_full_digest() {
        let plan = DeletionPlan::from_input(base_input()).unwrap();
        assert_ne!(
            plan.short_fingerprint().as_str(),
            plan.canonical_digest.as_str()
        );
    }

    #[test]
    fn digest_changes_across_edit_matrix() {
        let left = DeletionPlan::from_input(base_input()).unwrap();

        for (nonce_suffix, factor) in [
            ("a1", "recent"),
            ("b2", "coverage"),
            ("c3", "holder"),
            ("d4", "risk-escalated"),
            ("e5", "descendants"),
        ] {
            let mut edited = base_input();
            edited.nonce = format!("nonce-{nonce_suffix}");
            edited.items[0].risk_factors.push(RiskFactor::new(factor));
            let right = DeletionPlan::from_input(edited).unwrap();

            assert_ne!(
                left.canonical_digest.as_str(),
                right.canonical_digest.as_str()
            );
        }
    }

    #[test]
    fn validated_loader_rejects_copied_digest_tamper() {
        let plan = DeletionPlan::from_input(base_input()).unwrap();
        let mut value = serde_json::to_value(&plan).unwrap();
        value["nonce"] = json!("forged-nonce");
        value["canonical_digest"] = json!(plan.canonical_digest.as_str());

        let error = DeletionPlan::from_validated_value(value).unwrap_err();
        assert!(matches!(error, CanonicalPlanError::CanonicalDigestMismatch));
    }

    #[test]
    fn validated_loader_rejects_duplicate_action_ids() {
        let mut input = base_input();
        input
            .items
            .push(additional_trash_item("item-2", "action-top-2"));
        let mut plan = DeletionPlan::from_input(input).unwrap();
        plan.items[1].actions[0].action_id = "action-top-1".to_string();
        plan.items[1].top_level_action_id = "action-top-1".to_string();
        plan.canonical_digest = plan.canonical_digest_verified().unwrap();
        let value = serde_json::to_value(&plan).unwrap();

        let error = DeletionPlan::from_validated_value(value).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::DuplicateActionId { ref action_id }
                if action_id == "action-top-1"
        ));
    }

    #[test]
    fn validated_loader_rejects_incomplete_subtree() {
        let mut plan = DeletionPlan::from_input(base_input()).unwrap();
        plan.items[0].subtree_complete = false;
        plan.canonical_digest = plan.canonical_digest_verified().unwrap();
        let value = serde_json::to_value(&plan).unwrap();

        let error = DeletionPlan::from_validated_value(value).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::IncompleteSubtree { ref item_id } if item_id == "item-1"
        ));
    }

    #[test]
    fn validated_loader_rejects_missing_descendant_manifest() {
        let mut plan = DeletionPlan::from_input(permanent_multi_action_input()).unwrap();
        plan.items[0].descendant_manifest_digest = None;
        plan.canonical_digest = plan.canonical_digest_verified().unwrap();
        let value = serde_json::to_value(&plan).unwrap();

        let error = DeletionPlan::from_validated_value(value).unwrap_err();
        assert!(matches!(
            error,
            CanonicalPlanError::MissingDescendantManifest { ref item_id }
                if item_id == "item-1"
        ));
    }

    #[test]
    fn validated_loader_rejects_noncanonical_ttl() {
        let mut plan = DeletionPlan::from_input(base_input()).unwrap();
        plan.expires_at_unix_ms += 1;
        plan.canonical_digest = plan.canonical_digest_verified().unwrap();
        let value = serde_json::to_value(&plan).unwrap();

        let error = DeletionPlan::from_validated_value(value).unwrap_err();
        assert!(matches!(error, CanonicalPlanError::InvalidPlanTtl { .. }));
    }

    #[test]
    fn validated_loader_rejects_ttl_overflow() {
        let plan = DeletionPlan::from_input(base_input()).unwrap();
        let mut value = serde_json::to_value(&plan).unwrap();
        value["created_at_unix_ms"] = json!(u128::MAX.to_string());
        value["expires_at_unix_ms"] = json!(u128::MAX.to_string());

        let error = DeletionPlan::from_validated_value(value).unwrap_err();
        assert!(matches!(error, CanonicalPlanError::InvalidPlanTtl { .. }));
    }

    #[test]
    fn validated_loader_rejects_forged_aggregate_risk() {
        let mut plan = DeletionPlan::from_input(base_input()).unwrap();
        plan.aggregate_risk.tier = RiskTier::R1;
        plan.canonical_digest = plan.canonical_digest_verified().unwrap();
        let value = serde_json::to_value(&plan).unwrap();

        let error = DeletionPlan::from_validated_value(value).unwrap_err();
        assert!(matches!(error, CanonicalPlanError::AggregateRiskMismatch));
    }

    #[test]
    fn plan_expires_at_the_exact_deadline() {
        let input = base_input();
        let deadline = input.created_at + PLAN_TTL;
        let plan = DeletionPlan::from_input(input).unwrap();

        assert!(plan.is_expired_at(deadline));
    }

    #[test]
    fn plan_creation_time_rejects_future_and_invalid_clock_values() {
        let input = base_input();
        let created_at = input.created_at;
        let plan = DeletionPlan::from_input(input).unwrap();

        assert!(plan.is_created_after(created_at - Duration::from_millis(1)));
        assert!(!plan.is_created_after(created_at));
        assert!(!plan.is_created_after(created_at + Duration::from_millis(1)));
        assert!(plan.is_created_after(UNIX_EPOCH - Duration::from_millis(1)));
    }
}
