use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use sweepx_canonical::{
    CanonicalError, attention_fingerprint_from_digest_hex, canonical_json_bytes, plan_digest_hex,
};

const PLAN_SCHEMA: &str = "sweepx.plan/v1";
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItemDigest(PlanDigest);

impl PlanItemDigest {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
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
    pub fn from_input(input: DeletionPlanInput) -> Result<Self, CanonicalPlanError> {
        if input.items.is_empty() {
            return Err(CanonicalPlanError::EmptyPlan);
        }

        let created_at = to_unix_millis(input.created_at)?;
        let expires_at = created_at + PLAN_TTL.as_millis();
        let items = input
            .items
            .into_iter()
            .map(PlanItem::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        validate_mode_and_risk(input.mode, &items)?;

        let aggregate_tier = items
            .iter()
            .map(|item| item.risk_tier)
            .max()
            .expect("validated non-empty items");
        let aggregate_risk = AggregateRisk {
            tier: aggregate_tier,
            factors: items
                .iter()
                .flat_map(|item| item.risk_factors.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        };

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
            Ok(now_ms) => now_ms > self.expires_at_unix_ms,
            Err(_) => true,
        }
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
        validate_mode_and_risk(plan.mode, &plan.items)?;
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

        Ok(Self {
            item_id: input.item_id,
            candidate_id: input.candidate_id,
            explanation_digest: input.explanation_digest,
            top_level_action_id: input.top_level_action_id,
            target: input.target,
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
    #[error("trash and permanent modes cannot be mixed")]
    MixedModes,
    #[error("permanent mode requires every action to be R4")]
    PermanentRequiresR4,
    #[error("blocked actions cannot appear in a plan")]
    BlockedActionInPlan,
    #[error("failed to derive canonical digest: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("failed to parse plan json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system time is outside representable unix milliseconds")]
    InvalidTimestamp,
    #[error("stored canonical digest does not match the recomputed digest")]
    CanonicalDigestMismatch,
    #[error("invalid field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
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
    if actions.is_empty() {
        return Err(CanonicalPlanError::InvalidField {
            field: "actions",
            reason: "expected at least one action".to_string(),
        });
    }
    Ok(PlanItem {
        item_id: required_string(value, "item_id")?,
        candidate_id: required_string(value, "candidate_id")?,
        explanation_digest: ExplanationDigest::new(required_string(value, "explanation_digest")?),
        top_level_action_id: required_string(value, "top_level_action_id")?,
        target: TargetIdentity::new(required_string(value, "target")?),
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
        descendant_manifest_digest: value
            .get("descendant_manifest_digest")
            .map(|entry| {
                entry.as_str().map(ManifestDigest::new).ok_or_else(|| {
                    CanonicalPlanError::InvalidField {
                        field: "descendant_manifest_digest",
                        reason: "expected string or null".to_string(),
                    }
                })
            })
            .transpose()?,
        actions,
    })
}

fn parse_action(value: &Value) -> Result<PlanAction, CanonicalPlanError> {
    Ok(PlanAction {
        action_id: required_string(value, "action_id")?,
        manifest_digest: value
            .get("manifest_digest")
            .map(|entry| {
                entry.as_str().map(ManifestDigest::new).ok_or_else(|| {
                    CanonicalPlanError::InvalidField {
                        field: "manifest_digest",
                        reason: "expected string or null".to_string(),
                    }
                })
            })
            .transpose()?,
        risk_tier: parse_risk_tier("risk_tier", &required_string(value, "risk_tier")?)?,
    })
}

fn validate_mode_and_risk(
    mode: DeletionMode,
    items: &[PlanItem],
) -> Result<(), CanonicalPlanError> {
    let tiers = items
        .iter()
        .flat_map(|item| item.actions.iter())
        .map(|action| action.risk_tier)
        .collect::<Vec<_>>();

    if tiers.contains(&RiskTier::Blocked) {
        return Err(CanonicalPlanError::BlockedActionInPlan);
    }

    if mode == DeletionMode::Permanent && tiers.iter().any(|tier| *tier != RiskTier::R4) {
        return Err(CanonicalPlanError::PermanentRequiresR4);
    }

    Ok(())
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
}
