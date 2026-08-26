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
#[allow(dead_code)] // Reserved for the future crate-internal trusted approval broker.
pub(crate) enum ApprovalConfirmationEvidence {
    NativeFirstPartyLocalModal,
    TrustedForegroundTerminal { challenge_text: String },
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for the future crate-internal trusted approval broker.
pub(crate) struct HumanApprovalRequest {
    pub(crate) approval_id: String,
    pub(crate) workflow_session: String,
    pub(crate) nonce: String,
    pub(crate) confirmation_evidence: ApprovalConfirmationEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)] // Reserved for the future crate-internal dangerous-delete admission path.
pub(crate) enum DangerousSource {
    ExplicitDangerousDelete,
}

/// Explicit authority for the deterministic P3 simulator.
///
/// This is the only authorization request that can be constructed outside this crate. It does
/// not represent human approval or permission to invoke a native deletion adapter.
#[derive(Debug, Clone)]
pub struct SimulatedAuthorizationRequest {
    authorization_id: String,
    workflow_session: String,
    nonce: String,
}

impl SimulatedAuthorizationRequest {
    pub fn new(
        authorization_id: impl Into<String>,
        workflow_session: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            authorization_id: authorization_id.into(),
            workflow_session: workflow_session.into(),
            nonce: nonce.into(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct ExecutionAuthorization {
    #[serde(flatten)]
    kind: AuthorizationKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
enum AuthorizationKind {
    #[allow(dead_code)]
    HumanApproval(HumanApprovalRecord),
    #[allow(dead_code)]
    ExplicitDangerousDelete(DangerousDeleteRecord),
    DeterministicSimulation(SimulatedAuthorizationRecord),
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
    workflow_session: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SimulatedAuthorizationRecord {
    authorization_id: String,
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
    user_identity: String,
    host_instance_id: String,
    workflow_session: String,
    issued_at: SystemTime,
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

    pub fn is_deterministic_simulation(&self) -> bool {
        matches!(self.kind, AuthorizationKind::DeterministicSimulation(_))
    }

    pub fn authorization_id(&self) -> &str {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => &record.approval_id,
            AuthorizationKind::ExplicitDangerousDelete(record) => &record.authorization_id,
            AuthorizationKind::DeterministicSimulation(record) => &record.authorization_id,
        }
    }

    pub fn plan_digest(&self) -> &PlanDigest {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => &record.plan_digest,
            AuthorizationKind::ExplicitDangerousDelete(record) => &record.plan_digest,
            AuthorizationKind::DeterministicSimulation(record) => &record.plan_digest,
        }
    }

    pub fn mode(&self) -> DeletionMode {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => record.approved_mode,
            AuthorizationKind::ExplicitDangerousDelete(record) => record.exact_mode,
            AuthorizationKind::DeterministicSimulation(record) => record.exact_mode,
        }
    }

    pub fn state(&self) -> AuthorizationState {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => record.consumed_state,
            AuthorizationKind::ExplicitDangerousDelete(record) => record.consumed_state,
            AuthorizationKind::DeterministicSimulation(record) => record.consumed_state,
        }
    }

    pub fn expires_at(&self) -> SystemTime {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => record.expires_at,
            AuthorizationKind::ExplicitDangerousDelete(record) => record.expires_at,
            AuthorizationKind::DeterministicSimulation(record) => record.expires_at,
        }
    }

    fn issued_at(&self) -> SystemTime {
        match &self.kind {
            AuthorizationKind::HumanApproval(record) => record.approved_at,
            AuthorizationKind::ExplicitDangerousDelete(record) => record.invoked_at,
            AuthorizationKind::DeterministicSimulation(record) => record.issued_at,
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
            AuthorizationKind::DeterministicSimulation(record) => SelectedActionSet {
                mode: record.exact_mode,
                item_ids: record.authorized_item_ids.clone(),
                action_ids: record.authorized_action_ids.clone(),
                item_count: record.authorized_item_count,
                action_count: record.authorized_action_count,
                descendant_manifest_digests: record.authorized_descendant_manifest_digests.clone(),
            },
        }
    }

    pub fn audit_binding(
        &self,
        plan: &DeletionPlan,
        batch_id: sweepx_audit::BatchId,
        workflow_session: sweepx_audit::SessionId,
    ) -> Result<sweepx_audit::AuthorizationBinding, AuditBindingError> {
        if !self.is_deterministic_simulation() {
            return Err(AuditBindingError::SimulationAuthorizationRequired);
        }
        plan.verify_canonical_digest()?;
        if self.plan_digest() != &plan.canonical_digest || self.mode() != plan.mode {
            return Err(AuditBindingError::AuthorizationDoesNotMatchPlan);
        }
        let selected = plan.selected_action_set();
        if self.exact_action_set() != selected {
            return Err(AuditBindingError::AuthorizationDoesNotMatchPlan);
        }
        let source = sweepx_audit::AuthorizationSource::DeterministicSimulation;
        let mode = match plan.mode {
            DeletionMode::Trash => sweepx_audit::RequestedMode::Trash,
            DeletionMode::Permanent => sweepx_audit::RequestedMode::Permanent,
        };
        let item_ids = plan
            .items
            .iter()
            .map(|item| sweepx_audit::ItemId::new(item.item_id.clone()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut action_ids = BTreeSet::new();
        let mut item_by_action = BTreeMap::new();
        let mut risk_by_action = BTreeMap::new();
        for item in &plan.items {
            let audit_item_id = sweepx_audit::ItemId::new(item.item_id.clone())?;
            for action in &item.actions {
                let audit_action_id = sweepx_audit::ActionId::new(action.action_id.clone())?;
                if !action_ids.insert(audit_action_id.clone())
                    || item_by_action
                        .insert(audit_action_id.clone(), audit_item_id.clone())
                        .is_some()
                {
                    return Err(AuditBindingError::DuplicateActionId(
                        action.action_id.clone(),
                    ));
                }
                risk_by_action.insert(audit_action_id, audit_risk(action.risk_tier)?);
            }
        }
        let (user_identity, host_instance_id, bound_workflow_session) = match &self.kind {
            AuthorizationKind::HumanApproval(record) => (
                record.approving_user_identity.clone(),
                record.host_instance_id.clone(),
                record.workflow_session.clone(),
            ),
            AuthorizationKind::ExplicitDangerousDelete(record) => (
                record.invoking_user_identity.clone(),
                record.host_instance_id.clone(),
                record.workflow_session.clone(),
            ),
            AuthorizationKind::DeterministicSimulation(record) => (
                record.user_identity.clone(),
                record.host_instance_id.clone(),
                record.workflow_session.clone(),
            ),
        };
        if user_identity != plan.user_identity || host_instance_id != plan.host_instance_id {
            return Err(AuditBindingError::PrincipalOrHostMismatch);
        }
        if workflow_session != sweepx_audit::SessionId::new(bound_workflow_session)? {
            return Err(AuditBindingError::WorkflowSessionMismatch);
        }
        Ok(sweepx_audit::AuthorizationBinding {
            authorization_id: sweepx_audit::AuthorizationId::new(
                self.authorization_id().to_string(),
            )?,
            authorization_source: source,
            batch_id,
            plan_id: sweepx_audit::PlanId::new(plan.plan_id.as_str().to_string())?,
            plan_digest: sweepx_audit::DigestString::new(
                plan.canonical_digest.as_str().to_string(),
            )?,
            requested_mode: mode,
            item_ids,
            action_ids,
            item_by_action,
            action_count: plan.action_count() as u64,
            risk_by_action,
            policy_version: plan.safety_policy_version.clone(),
            policy_digest: sweepx_audit::DigestString::new(plan.safety_policy_digest.clone())?,
            protected_anchor_snapshot_digest: sweepx_audit::DigestString::new(
                plan.protected_anchor_snapshot_digest.clone(),
            )?,
            adapter_capabilities_digest: sweepx_audit::DigestString::new(
                plan.adapter_capabilities_digest.clone(),
            )?,
            cleaner_set_digest: sweepx_audit::DigestString::new(plan.cleaner_set_digest.clone())?,
            host_instance_id: sweepx_audit::HostId::new(host_instance_id)?,
            user_identity: sweepx_audit::UserId::new(user_identity)?,
            workflow_session,
        })
    }

    /// Verifies that a durable audit claim carries the complete authority sealed by this
    /// authorization and plan. The caller cannot supply a substitute workflow session because
    /// the expected binding is reconstructed from the persisted binding's batch identifier and
    /// then compared field-for-field, including the session, principal, host, policy, anchors,
    /// adapter capabilities, cleaner set, exact item/action mapping, and risks.
    pub fn matches_audit_binding(
        &self,
        plan: &DeletionPlan,
        binding: &sweepx_audit::AuthorizationBinding,
    ) -> Result<(), AuditBindingError> {
        let expected = self.audit_binding(
            plan,
            binding.batch_id.clone(),
            binding.workflow_session.clone(),
        )?;
        if expected != *binding {
            return Err(AuditBindingError::BindingMismatch);
        }
        Ok(())
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

        let now = clock.now();
        if plan.is_not_yet_valid_at(now) || now < self.issued_at() {
            return Err(AuthorizationMatchError::NotYetValid);
        }
        if now >= self.expires_at() || plan.is_expired_at(now) {
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
            AuthorizationKind::DeterministicSimulation(record) => {
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
            AuthorizationKind::DeterministicSimulation(mut record) => {
                transition_claim(&mut record.consumed_state, fence_epoch)?;
                Ok(Self {
                    kind: AuthorizationKind::DeterministicSimulation(record),
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
            AuthorizationKind::DeterministicSimulation(mut record) => {
                transition_consume(&mut record.consumed_state)?;
                Ok(Self {
                    kind: AuthorizationKind::DeterministicSimulation(record),
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

fn audit_risk(risk: RiskTier) -> Result<sweepx_audit::RiskTier, AuditBindingError> {
    match risk {
        RiskTier::R1 => Ok(sweepx_audit::RiskTier::R1),
        RiskTier::R2 => Ok(sweepx_audit::RiskTier::R2),
        RiskTier::R3 => Ok(sweepx_audit::RiskTier::R3),
        RiskTier::R4 => Ok(sweepx_audit::RiskTier::R4),
        RiskTier::Blocked => Err(AuditBindingError::BlockedRisk),
    }
}

#[derive(Debug, Error)]
pub enum AuditBindingError {
    #[error("P3 audit binding requires deterministic-simulation authorization")]
    SimulationAuthorizationRequired,
    #[error("plan integrity validation failed: {0}")]
    PlanIntegrity(#[from] CanonicalPlanError),
    #[error("audit identifier validation failed: {0}")]
    Audit(#[from] sweepx_audit::AuditError),
    #[error("authorization does not match the exact plan")]
    AuthorizationDoesNotMatchPlan,
    #[error("audit binding differs from the sealed authorization")]
    BindingMismatch,
    #[error("authorization principal or host differs from the plan")]
    PrincipalOrHostMismatch,
    #[error("workflow session differs from the sealed authorization")]
    WorkflowSessionMismatch,
    #[error("duplicate action id in plan: {0}")]
    DuplicateActionId(String),
    #[error("blocked risk cannot be registered for execution")]
    BlockedRisk,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for the future crate-internal dangerous-delete admission path.
pub(crate) struct PermanentAuthorizationRequest {
    pub(crate) authorization_id: String,
    pub(crate) workflow_session: String,
    pub(crate) nonce: String,
}

impl PermanentAuthorizationRequest {
    #[allow(dead_code)]
    pub(crate) fn bind_to_plan(
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
    #[allow(dead_code)]
    pub(crate) fn bind_to_plan(
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
                workflow_session: self.workflow_session,
                approved_at,
                expires_at,
                confirmation_evidence: self.confirmation_evidence,
                nonce: self.nonce,
                consumed_state: AuthorizationState::Unused,
            }),
        })
    }
}

impl SimulatedAuthorizationRequest {
    /// Binds an explicitly simulation-only authorization to one exact canonical plan.
    pub fn bind_to_plan(
        self,
        plan: &DeletionPlan,
        user_identity: impl Into<String>,
        host_instance_id: impl Into<String>,
        clock: &dyn Clock,
    ) -> Result<ExecutionAuthorization, AuthorizationBindError> {
        let issued_at = clock.now();
        let expires_at = issued_at
            .checked_add(APPROVAL_TTL)
            .ok_or(AuthorizationBindError::InvalidClock)?;
        let selected = plan.selected_action_set();
        let risk_by_action = planned_risk_by_action(plan);
        let authorized_max_risk = risk_by_action
            .values()
            .copied()
            .max()
            .unwrap_or(plan.aggregate_risk.tier);

        Ok(ExecutionAuthorization {
            kind: AuthorizationKind::DeterministicSimulation(SimulatedAuthorizationRecord {
                authorization_id: self.authorization_id,
                plan_id: plan.plan_id.as_str().to_string(),
                plan_digest: plan.canonical_digest.clone(),
                exact_mode: plan.mode,
                authorized_item_ids: selected.item_ids,
                authorized_action_ids: selected.action_ids,
                authorized_item_count: selected.item_count,
                authorized_action_count: selected.action_count,
                authorized_risk_by_action: risk_by_action,
                authorized_descendant_manifest_digests: selected.descendant_manifest_digests,
                authorized_max_risk,
                plan_schema_version: plan.schema.clone(),
                candidate_version: plan.candidate_version.clone(),
                scanner_version: plan.scanner_version.clone(),
                policy_version: plan.safety_policy_version.clone(),
                policy_digest: plan.safety_policy_digest.clone(),
                protected_anchor_snapshot_digest: plan.protected_anchor_snapshot_digest.clone(),
                adapter_capabilities_digest: plan.adapter_capabilities_digest.clone(),
                cleaner_set_digest: plan.cleaner_set_digest.clone(),
                user_identity: user_identity.into(),
                host_instance_id: host_instance_id.into(),
                workflow_session: self.workflow_session,
                issued_at,
                expires_at,
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
    #[error("authorization or plan is not yet valid")]
    NotYetValid,
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
            plan_id: PlanId::new("plan-0001"),
            nonce: "nonce-1".to_string(),
            created_at: UNIX_EPOCH + Duration::from_secs(1),
            host_instance_id: "host-0001".to_string(),
            user_identity: "user-0001".to_string(),
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
                item_id: "item-0001".to_string(),
                candidate_id: "candidate-1".to_string(),
                explanation_digest: ExplanationDigest::new("explain-1"),
                top_level_action_id: "action-0001".to_string(),
                target: TargetIdentity::new("target-1"),
                risk_tier: RiskTier::R4,
                risk_factors: vec![RiskFactor::new("irreversible")],
                subtree_complete: true,
                descendant_manifest_digest: Some(ManifestDigest::new("manifest-1")),
                actions: vec![
                    PlanAction::new("action-0001", RiskTier::R4)
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
        .bind_to_plan(&plan, "user-0001", "host-0001", &clock)
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
            workflow_session: "workflow-1".to_string(),
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
        .bind_to_plan(&plan, "user-0001", "host-0001", &clock)
        .unwrap()
        .claim(5)
        .unwrap();

        assert!(auth.is_human_approval());
        assert!(auth.matches_plan(&plan, &clock).is_ok());
    }

    #[test]
    fn real_authorization_kinds_cannot_create_p3_audit_bindings() {
        let plan = permanent_plan();
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let human = HumanApprovalRequest {
            approval_id: "approval-internal-only".to_string(),
            workflow_session: "workflow-internal-only".to_string(),
            nonce: "nonce-internal-only".to_string(),
            confirmation_evidence: ApprovalConfirmationEvidence::NativeFirstPartyLocalModal,
        }
        .bind_to_plan(&plan, "user-0001", "host-0001", &clock)
        .unwrap();
        let dangerous = PermanentAuthorizationRequest {
            authorization_id: "danger-internal-only".to_string(),
            workflow_session: "workflow-internal-only".to_string(),
            nonce: "danger-nonce-internal-only".to_string(),
        }
        .bind_to_plan(&plan, "user-0001", "host-0001", &clock)
        .unwrap();

        for authorization in [human, dangerous] {
            assert!(matches!(
                authorization.audit_binding(
                    &plan,
                    sweepx_audit::BatchId::new("batch-internal-only").unwrap(),
                    sweepx_audit::SessionId::new("workflow-internal-only").unwrap(),
                ),
                Err(AuditBindingError::SimulationAuthorizationRequired)
            ));
        }
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
        .bind_to_plan(&plan, "user-0001", "host-0001", &clock)
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

    #[test]
    fn authorization_expires_at_the_exact_deadline() {
        let plan = permanent_plan();
        let issued_at = UNIX_EPOCH + Duration::from_secs(10);
        let issue_clock = FixedClock::new(issued_at);
        let auth = PermanentAuthorizationRequest {
            authorization_id: "auth-deadline".to_string(),
            workflow_session: "workflow-deadline".to_string(),
            nonce: "nonce-deadline".to_string(),
        }
        .bind_to_plan(&plan, "user-0001", "host-0001", &issue_clock)
        .unwrap()
        .claim(1)
        .unwrap();
        let deadline = FixedClock::new(issued_at + APPROVAL_TTL);

        assert!(matches!(
            auth.matches_plan(&plan, &deadline).unwrap_err(),
            AuthorizationMatchError::Expired
        ));
    }

    #[test]
    fn authorization_rejects_time_before_plan_creation() {
        let plan = permanent_plan();
        let issued_at = UNIX_EPOCH + Duration::from_millis(500);
        let auth = SimulatedAuthorizationRequest::new(
            "simulation-future-plan",
            "workflow-future-plan",
            "nonce-future-plan",
        )
        .bind_to_plan(&plan, "user-0001", "host-0001", &FixedClock::new(issued_at))
        .unwrap()
        .claim(2)
        .unwrap();

        assert!(matches!(
            auth.matches_plan(
                &plan,
                &FixedClock::new(UNIX_EPOCH + Duration::from_millis(999))
            )
            .unwrap_err(),
            AuthorizationMatchError::NotYetValid
        ));
    }

    #[test]
    fn plan_creation_time_is_inclusive() {
        let plan = permanent_plan();
        let created_at = UNIX_EPOCH + Duration::from_secs(1);
        let authorization = SimulatedAuthorizationRequest::new(
            "simulation-plan-start",
            "workflow-plan-start",
            "nonce-plan-start",
        )
        .bind_to_plan(
            &plan,
            "user-0001",
            "host-0001",
            &FixedClock::new(created_at),
        )
        .unwrap()
        .claim(4)
        .unwrap();

        assert!(
            authorization
                .matches_plan(&plan, &FixedClock::new(created_at))
                .is_ok()
        );
    }

    #[test]
    fn authorization_rejects_time_before_issuance() {
        let plan = permanent_plan();
        let issued_at = UNIX_EPOCH + Duration::from_secs(10);
        let auth = SimulatedAuthorizationRequest::new(
            "simulation-future-authorization",
            "workflow-future-authorization",
            "nonce-future-authorization",
        )
        .bind_to_plan(&plan, "user-0001", "host-0001", &FixedClock::new(issued_at))
        .unwrap()
        .claim(3)
        .unwrap();

        assert!(matches!(
            auth.matches_plan(
                &plan,
                &FixedClock::new(issued_at - Duration::from_millis(1))
            )
            .unwrap_err(),
            AuthorizationMatchError::NotYetValid
        ));
    }

    #[test]
    fn public_simulation_authorization_has_distinct_provenance() {
        let plan = permanent_plan();
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let authorization = SimulatedAuthorizationRequest::new(
            "simulation-distinct",
            "workflow-distinct",
            "nonce-distinct",
        )
        .bind_to_plan(&plan, "user-0001", "host-0001", &clock)
        .unwrap();
        let binding = authorization
            .audit_binding(
                &plan,
                sweepx_audit::BatchId::new("batch-distinct").unwrap(),
                sweepx_audit::SessionId::new("workflow-distinct").unwrap(),
            )
            .unwrap();

        assert!(authorization.is_deterministic_simulation());
        assert!(!authorization.is_human_approval());
        assert!(!authorization.is_explicit_dangerous_delete());
        assert_eq!(
            binding.authorization_source,
            sweepx_audit::AuthorizationSource::DeterministicSimulation
        );
    }
}
