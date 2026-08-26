use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use thiserror::Error;

use crate::plan::{
    CanonicalPlanError, DeletionMode, DeletionPlan, ManifestDigest, PlanDigest, RiskTier,
    SelectedActionSet,
};
use crate::time::Clock;

pub const APPROVAL_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationState {
    Unused,
    Claimed { fence_epoch: u64 },
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalConfirmationEvidence {
    NativeFirstPartyLocalModal,
    TrustedForegroundTerminal { challenge_text: String },
}

#[derive(Debug, Clone)]
pub struct HumanApprovalRequest {
    pub approval_id: String,
    pub nonce: String,
    pub confirmation_evidence: ApprovalConfirmationEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DangerousSource {
    ExplicitDangerousDelete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionAuthorization {
    #[serde(flatten)]
    kind: AuthorizationKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
enum AuthorizationKind {
    HumanApproval(HumanApprovalRecord),
    ExplicitDangerousDelete(DangerousDeleteRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct HumanApprovalRecord {
    approval_id: String,
    plan_id: String,
    plan_digest: PlanDigest,
    approved_mode: DeletionMode,
    approved_item_ids: BTreeSet<String>,
    approved_action_ids: BTreeSet<String>,
    approved_item_count: usize,
    approved_action_count: usize,
    approved_risk_by_action: BTreeMap<String, RiskTier>,
    approved_descendant_manifest_digests: BTreeMap<String, ManifestDigest>,
    approved_max_risk: RiskTier,
    plan_schema_version: String,
    candidate_version: String,
    scanner_version: String,
    policy_version: String,
    policy_digest: String,
    protected_anchor_snapshot_digest: String,
    adapter_capabilities_digest: String,
    cleaner_set_digest: String,
    approving_user_identity: String,
    host_instance_id: String,
    approved_at: SystemTime,
    expires_at: SystemTime,
    confirmation_evidence: ApprovalConfirmationEvidence,
    nonce: String,
    consumed_state: AuthorizationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DangerousDeleteRecord {
    authorization_id: String,
    source: DangerousSource,
    plan_id: String,
    plan_digest: PlanDigest,
    exact_mode: DeletionMode,
    authorized_item_ids: BTreeSet<String>,
    authorized_action_ids: BTreeSet<String>,
    authorized_item_count: usize,
    authorized_action_count: usize,
    authorized_risk_by_action: BTreeMap<String, RiskTier>,
    authorized_descendant_manifest_digests: BTreeMap<String, ManifestDigest>,
    authorized_max_risk: RiskTier,
    plan_schema_version: String,
    candidate_version: String,
    scanner_version: String,
    policy_version: String,
    policy_digest: String,
    protected_anchor_snapshot_digest: String,
    adapter_capabilities_digest: String,
    cleaner_set_digest: String,
    invoking_user_identity: String,
    host_instance_id: String,
    workflow_session: String,
    invoked_at: SystemTime,
    expires_at: SystemTime,
    nonce: String,
    consumed_state: AuthorizationState,
}

impl ExecutionAuthorization {
    pub fn is_human_approval(&self) -> bool {
        matches!(self.kind, AuthorizationKind::HumanApproval(_))
    }

    pub fn is_explicit_dangerous_delete(&self) -> bool {
        matches!(self.kind, AuthorizationKind::ExplicitDangerousDelete(_))
    }

    pub fn authorization_id(&self) -> &str {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => &record.approval_id,
            AuthorizationKind::ExplicitDangerousDelete(record) => &record.authorization_id,
        }
    }

    pub fn plan_digest(&self) -> &PlanDigest {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => &record.plan_digest,
            AuthorizationKind::ExplicitDangerousDelete(record) => &record.plan_digest,
        }
    }

    pub fn mode(&self) -> DeletionMode {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => record.approved_mode,
            AuthorizationKind::ExplicitDangerousDelete(record) => record.exact_mode,
        }
    }

    pub fn state(&self) -> AuthorizationState {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => record.consumed_state,
            AuthorizationKind::ExplicitDangerousDelete(record) => record.consumed_state,
        }
    }

    pub fn expires_at(&self) -> SystemTime {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => record.expires_at,
            AuthorizationKind::ExplicitDangerousDelete(record) => record.expires_at,
        }
    }

    pub fn exact_action_set(&self) -> SelectedActionSet {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => SelectedActionSet {
                mode: record.approved_mode,
                item_ids: record.approved_item_ids.clone(),
                action_ids: record.approved_action_ids.clone(),
                item_count: record.approved_item_count,
                action_count: record.approved_action_count,
                descendant_manifest_digests: record
                    .approved_descendant_manifest_digests
                    .iter()
                    .map(|(item, digest)| (item.clone(), digest.clone()))
                    .collect(),
            },
            AuthorizationKind::ExplicitDangerousDelete(record) => SelectedActionSet {
                mode: record.exact_mode,
                item_ids: record.authorized_item_ids.clone(),
                action_ids: record.authorized_action_ids.clone(),
                item_count: record.authorized_item_count,
                action_count: record.authorized_action_count,
                descendant_manifest_digests: record
                    .authorized_descendant_manifest_digests
                    .iter()
                    .map(|(item, digest)| (item.clone(), digest.clone()))
                    .collect(),
            },
        }
    }

    pub fn matches_plan(
        &self,
        plan: &DeletionPlan,
        clock: &dyn Clock,
    ) -> Result<(), AuthorizationMatchError> {
        verify_plan_digest(plan)?;

        if self.plan_digest() != &plan.canonical_digest {
            return Err(AuthorizationMatchError::DigestMismatch);
        }

        if self.mode() != plan.mode {
            return Err(AuthorizationMatchError::ModeMismatch);
        }

        self.fence_epoch()?;

        if clock.now() > self.expires_at() || plan.is_expired_at(clock.now()) {
            return Err(AuthorizationMatchError::Expired);
        }

        let exact = self.exact_action_set();
        let planned = plan.selected_action_set();
        if exact.mode != planned.mode
            || exact.item_ids != planned.item_ids
            || exact.action_ids != planned.action_ids
            || exact.item_count != planned.item_count
            || exact.action_count != planned.action_count
            || exact.descendant_manifest_digests != planned.descendant_manifest_digests
        {
            return Err(AuthorizationMatchError::ActionSetMismatch);
        }

        match &self.kind {
            AuthorizationKind::HumanApproval(record) => {
                if record.approved_risk_by_action != planned_risk_by_action(plan) {
                    return Err(AuthorizationMatchError::RiskBindingMismatch);
                }
                if record.plan_schema_version != plan.schema
                    || record.candidate_version != plan.candidate_version
                    || record.scanner_version != plan.scanner_version
                    || record.policy_version != plan.safety_policy_version
                    || record.policy_digest != plan.safety_policy_digest
                    || record.protected_anchor_snapshot_digest
                        != plan.protected_anchor_snapshot_digest
                    || record.adapter_capabilities_digest != plan.adapter_capabilities_digest
                    || record.cleaner_set_digest != plan.cleaner_set_digest
                {
                    return Err(AuthorizationMatchError::BindingMismatch);
                }
            }
            AuthorizationKind::ExplicitDangerousDelete(record) => {
                if record.exact_mode != DeletionMode::Permanent {
                    return Err(AuthorizationMatchError::DangerousDeleteRequiresPermanent);
                }
                if record.authorized_risk_by_action != planned_risk_by_action(plan) {
                    return Err(AuthorizationMatchError::RiskBindingMismatch);
                }
                if record.plan_schema_version != plan.schema
                    || record.candidate_version != plan.candidate_version
                    || record.scanner_version != plan.scanner_version
                    || record.policy_version != plan.safety_policy_version
                    || record.policy_digest != plan.safety_policy_digest
                    || record.protected_anchor_snapshot_digest
                        != plan.protected_anchor_snapshot_digest
                    || record.adapter_capabilities_digest != plan.adapter_capabilities_digest
                    || record.cleaner_set_digest != plan.cleaner_set_digest
                {
                    return Err(AuthorizationMatchError::BindingMismatch);
                }
            }
        }

        Ok(())
    }

    pub fn claim(self, fence_epoch: u64) -> Result<Self, AuthorizationClaimError> {
        match self.kind {
            AuthorizationKind::HumanApproval(mut record) => {
                transition_claim(&mut record.consumed_state, fence_epoch)?;
                Ok(Self {
                    kind: AuthorizationKind::HumanApproval(record),
                })
            }
            AuthorizationKind::ExplicitDangerousDelete(mut record) => {
                transition_claim(&mut record.consumed_state, fence_epoch)?;
                Ok(Self {
                    kind: AuthorizationKind::ExplicitDangerousDelete(record),
                })
            }
        }
    }

    pub fn consume(self) -> Result<Self, AuthorizationConsumeError> {
        match self.kind {
            AuthorizationKind::HumanApproval(mut record) => {
                transition_consume(&mut record.consumed_state)?;
                Ok(Self {
                    kind: AuthorizationKind::HumanApproval(record),
                })
            }
            AuthorizationKind::ExplicitDangerousDelete(mut record) => {
                transition_consume(&mut record.consumed_state)?;
                Ok(Self {
                    kind: AuthorizationKind::ExplicitDangerousDelete(record),
                })
            }
        }
    }

    pub(crate) fn fence_epoch(&self) -> Result<u64, AuthorizationMatchError> {
        match self.state() {
            AuthorizationState::Claimed { fence_epoch } => Ok(fence_epoch),
            AuthorizationState::Unused | AuthorizationState::Consumed => {
                Err(AuthorizationMatchError::AuthorizationNotClaimed)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PermanentAuthorizationRequest {
    pub authorization_id: String,
    pub workflow_session: String,
    pub nonce: String,
}

impl PermanentAuthorizationRequest {
    pub fn bind_to_plan(
        self,
        plan: &DeletionPlan,
        invoking_user_identity: impl Into<String>,
        host_instance_id: impl Into<String>,
        clock: &dyn Clock,
    ) -> Result<ExecutionAuthorization, AuthorizationBindError> {
        if plan.mode != DeletionMode::Permanent {
            return Err(AuthorizationBindError::PermanentPlanRequired);
        }
        if plan.aggregate_risk.tier != RiskTier::R4 {
            return Err(AuthorizationBindError::DangerousDeleteRequiresR4);
        }

        let risk_by_action = planned_risk_by_action(plan);
        if risk_by_action.values().any(|tier| *tier != RiskTier::R4) {
            return Err(AuthorizationBindError::DangerousDeleteRequiresR4);
        }

        let selected = plan.selected_action_set();
        let invoked_at = clock.now();
        let expires_at = invoked_at
            .checked_add(APPROVAL_TTL)
            .ok_or(AuthorizationBindError::InvalidClock)?;

        Ok(ExecutionAuthorization {
            kind: AuthorizationKind::ExplicitDangerousDelete(DangerousDeleteRecord {
                authorization_id: self.authorization_id,
                source: DangerousSource::ExplicitDangerousDelete,
                plan_id: plan.plan_id.as_str().to_string(),
                plan_digest: plan.canonical_digest.clone(),
                exact_mode: plan.mode,
                authorized_item_ids: selected.item_ids,
                authorized_action_ids: selected.action_ids,
                authorized_item_count: selected.item_count,
                authorized_action_count: selected.action_count,
                authorized_risk_by_action: risk_by_action,
                authorized_descendant_manifest_digests: selected
                    .descendant_manifest_digests
                    .into_iter()
                    .collect(),
                authorized_max_risk: RiskTier::R4,
                plan_schema_version: plan.schema.clone(),
                candidate_version: plan.candidate_version.clone(),
                scanner_version: plan.scanner_version.clone(),
                policy_version: plan.safety_policy_version.clone(),
                policy_digest: plan.safety_policy_digest.clone(),
                protected_anchor_snapshot_digest: plan.protected_anchor_snapshot_digest.clone(),
                adapter_capabilities_digest: plan.adapter_capabilities_digest.clone(),
                cleaner_set_digest: plan.cleaner_set_digest.clone(),
                invoking_user_identity: invoking_user_identity.into(),
                host_instance_id: host_instance_id.into(),
                workflow_session: self.workflow_session,
                invoked_at,
                expires_at,
                nonce: self.nonce,
                consumed_state: AuthorizationState::Unused,
            }),
        })
    }
}

impl HumanApprovalRequest {
    pub fn bind_to_plan(
        self,
        plan: &DeletionPlan,
        approving_user_identity: impl Into<String>,
        host_instance_id: impl Into<String>,
        clock: &dyn Clock,
    ) -> Result<ExecutionAuthorization, AuthorizationBindError> {
        let approved_at = clock.now();
        let expires_at = approved_at
            .checked_add(APPROVAL_TTL)
            .ok_or(AuthorizationBindError::InvalidClock)?;
        let selected = plan.selected_action_set();
        let approved_risk_by_action = planned_risk_by_action(plan);
        let approved_max_risk = approved_risk_by_action
            .values()
            .copied()
            .max()
            .unwrap_or(plan.aggregate_risk.tier);

        Ok(ExecutionAuthorization {
            kind: AuthorizationKind::HumanApproval(HumanApprovalRecord {
                approval_id: self.approval_id,
                plan_id: plan.plan_id.as_str().to_string(),
                plan_digest: plan.canonical_digest.clone(),
                approved_mode: plan.mode,
                approved_item_ids: selected.item_ids,
                approved_action_ids: selected.action_ids,
                approved_item_count: selected.item_count,
                approved_action_count: selected.action_count,
                approved_risk_by_action,
                approved_descendant_manifest_digests: selected.descendant_manifest_digests,
                approved_max_risk,
                plan_schema_version: plan.schema.clone(),
                candidate_version: plan.candidate_version.clone(),
                scanner_version: plan.scanner_version.clone(),
                policy_version: plan.safety_policy_version.clone(),
                policy_digest: plan.safety_policy_digest.clone(),
                protected_anchor_snapshot_digest: plan.protected_anchor_snapshot_digest.clone(),
                adapter_capabilities_digest: plan.adapter_capabilities_digest.clone(),
                cleaner_set_digest: plan.cleaner_set_digest.clone(),
                approving_user_identity: approving_user_identity.into(),
                host_instance_id: host_instance_id.into(),
                approved_at,
                expires_at,
                confirmation_evidence: self.confirmation_evidence,
                nonce: self.nonce,
                consumed_state: AuthorizationState::Unused,
            }),
        })
    }
}

fn verify_plan_digest(plan: &DeletionPlan) -> Result<(), AuthorizationMatchError> {
    plan.verify_canonical_digest()
        .map_err(AuthorizationMatchError::PlanIntegrity)
}

fn planned_risk_by_action(plan: &DeletionPlan) -> BTreeMap<String, RiskTier> {
    plan.items
        .iter()
        .flat_map(|item| item.actions.iter())
        .map(|action| (action.action_id.clone(), action.risk_tier))
        .collect()
}

fn transition_claim(
    state: &mut AuthorizationState,
    fence_epoch: u64,
) -> Result<(), AuthorizationClaimError> {
    match state {
        AuthorizationState::Unused => {
            *state = AuthorizationState::Claimed { fence_epoch };
            Ok(())
        }
        AuthorizationState::Claimed { .. } => Err(AuthorizationClaimError::AlreadyClaimed),
        AuthorizationState::Consumed => Err(AuthorizationClaimError::AlreadyConsumed),
    }
}

fn transition_consume(state: &mut AuthorizationState) -> Result<(), AuthorizationConsumeError> {
    match state {
        AuthorizationState::Claimed { .. } => {
            *state = AuthorizationState::Consumed;
            Ok(())
        }
        AuthorizationState::Unused => Err(AuthorizationConsumeError::AuthorizationNotClaimed),
        AuthorizationState::Consumed => Err(AuthorizationConsumeError::AlreadyConsumed),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationBindError {
    #[error("dangerous delete requires a permanent plan")]
    PermanentPlanRequired,
    #[error("dangerous delete requires R4 for every action")]
    DangerousDeleteRequiresR4,
    #[error("clock cannot represent authorization ttl")]
    InvalidClock,
}

#[derive(Debug, Error)]
pub enum AuthorizationMatchError {
    #[error("plan canonical digest failed verification: {0}")]
    PlanIntegrity(CanonicalPlanError),
    #[error("authorization full digest does not match the plan digest")]
    DigestMismatch,
    #[error("authorization mode does not match the plan mode")]
    ModeMismatch,
    #[error("authorization requires claimed single-use state")]
    AuthorizationNotClaimed,
    #[error("authorization or plan has expired")]
    Expired,
    #[error("authorization exact item or action set differs from the plan")]
    ActionSetMismatch,
    #[error("authorization risk bindings differ from the plan actions")]
    RiskBindingMismatch,
    #[error("authorization schema/version/digest bindings differ from the plan")]
    BindingMismatch,
    #[error("explicit dangerous delete is only valid for permanent mode")]
    DangerousDeleteRequiresPermanent,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationClaimError {
    #[error("authorization is already claimed")]
    AlreadyClaimed,
    #[error("authorization has already been consumed")]
    AlreadyConsumed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationConsumeError {
    #[error("authorization must be claimed before it can be consumed")]
    AuthorizationNotClaimed,
    #[error("authorization has already been consumed")]
    AlreadyConsumed,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::plan::{
        DeletionPlanInput, ExplanationDigest, ManifestDigest, PlanAction, PlanId, PlanItemInput,
        RiskFactor, TargetIdentity,
    };
    use crate::time::FixedClock;

    use super::*;

    fn permanent_plan() -> DeletionPlan {
        DeletionPlan::from_input(DeletionPlanInput {
            plan_id: PlanId::new("plan-1"),
            nonce: "nonce-1".to_string(),
            created_at: UNIX_EPOCH + Duration::from_secs(1),
            host_instance_id: "host-1".to_string(),
            user_identity: "user-1".to_string(),
            scan_id: "scan-1".to_string(),
            scan_root_identity: "root-1".to_string(),
            mode: DeletionMode::Permanent,
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
                top_level_action_id: "action-1".to_string(),
                target: TargetIdentity::new("target-1"),
                risk_tier: RiskTier::R4,
                risk_factors: vec![RiskFactor::new("irreversible")],
                subtree_complete: true,
                descendant_manifest_digest: Some(ManifestDigest::new("manifest-1")),
                actions: vec![
                    PlanAction::new("action-1", RiskTier::R4)
                        .with_manifest_digest(ManifestDigest::new("manifest-1")),
                ],
            }],
        })
        .unwrap()
    }

    #[test]
    fn dangerous_delete_only_binds_to_permanent_r4_plan() {
        let plan = permanent_plan();
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let auth = PermanentAuthorizationRequest {
            authorization_id: "auth-1".to_string(),
            workflow_session: "workflow-1".to_string(),
            nonce: "nonce-auth".to_string(),
        }
        .bind_to_plan(&plan, "user-1", "host-1", &clock)
        .unwrap();

        assert!(auth.is_explicit_dangerous_delete());
        assert_eq!(auth.mode(), DeletionMode::Permanent);
    }

    #[test]
    fn human_approval_binds_to_exact_plan_digest() {
        let plan = permanent_plan();
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let auth = HumanApprovalRequest {
            approval_id: "approval-1".to_string(),
            nonce: "nonce-approval".to_string(),
            confirmation_evidence: ApprovalConfirmationEvidence::TrustedForegroundTerminal {
                challenge_text: format!(
                    "PERMANENT {} {} {}",
                    plan.items.len(),
                    plan.action_count(),
                    plan.short_fingerprint().as_str()
                ),
            },
        }
        .bind_to_plan(&plan, "user-1", "host-1", &clock)
        .unwrap()
        .claim(5)
        .unwrap();

        assert!(auth.is_human_approval());
        assert!(auth.matches_plan(&plan, &clock).is_ok());
    }

    #[test]
    fn full_digest_mismatch_never_authorizes() {
        let plan = permanent_plan();
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let auth = PermanentAuthorizationRequest {
            authorization_id: "auth-1".to_string(),
            workflow_session: "workflow-1".to_string(),
            nonce: "nonce-auth".to_string(),
        }
        .bind_to_plan(&plan, "user-1", "host-1", &clock)
        .unwrap();

        let mut other_input = DeletionPlanInput {
            plan_id: PlanId::new("plan-1"),
            nonce: "nonce-2".to_string(),
            created_at: UNIX_EPOCH + Duration::from_secs(1),
            host_instance_id: "host-1".to_string(),
            user_identity: "user-1".to_string(),
            scan_id: "scan-1".to_string(),
            scan_root_identity: "root-1".to_string(),
            mode: DeletionMode::Permanent,
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
                top_level_action_id: "action-1".to_string(),
                target: TargetIdentity::new("target-1"),
                risk_tier: RiskTier::R4,
                risk_factors: vec![RiskFactor::new("irreversible")],
                subtree_complete: true,
                descendant_manifest_digest: Some(ManifestDigest::new("manifest-1")),
                actions: vec![
                    PlanAction::new("action-1", RiskTier::R4)
                        .with_manifest_digest(ManifestDigest::new("manifest-1")),
                ],
            }],
        };
        other_input.items[0]
            .risk_factors
            .push(RiskFactor::new("changed"));
        let other = DeletionPlan::from_input(other_input).unwrap();

        assert!(matches!(
            auth.matches_plan(&other, &clock).unwrap_err(),
            AuthorizationMatchError::DigestMismatch
        ));
    }
}
