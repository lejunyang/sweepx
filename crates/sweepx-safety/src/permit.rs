use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::authorization::{AuthorizationMatchError, ExecutionAuthorization};
use crate::plan::{DeletionMode, DeletionPlan, PlanDigest, RiskTier};
use crate::time::Clock;

pub const PERMIT_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct PreflightPermitRequest {
    pub expected_item_id: String,
    pub expected_action_id: String,
    pub revalidation_digest: String,
    pub final_parent_identity: String,
    pub final_object_identity: String,
    pub final_filesystem_object_domain_identity: String,
    pub final_volume_or_mount_identity: String,
    pub one_shot_nonce: String,
}

#[derive(Debug)]
pub struct PreflightPermit {
    #[allow(dead_code)]
    plan_id: String,
    #[allow(dead_code)]
    item_id: String,
    #[allow(dead_code)]
    action_id: String,
    plan_digest: PlanDigest,
    #[allow(dead_code)]
    authorization_id: String,
    #[allow(dead_code)]
    mode: DeletionMode,
    #[allow(dead_code)]
    risk_tier: RiskTier,
    #[allow(dead_code)]
    policy_version: String,
    #[allow(dead_code)]
    policy_digest: String,
    #[allow(dead_code)]
    protected_anchor_snapshot_digest: String,
    #[allow(dead_code)]
    validated_at: SystemTime,
    expires_at: SystemTime,
    #[allow(dead_code)]
    final_parent_identity: String,
    #[allow(dead_code)]
    final_object_identity: String,
    #[allow(dead_code)]
    final_filesystem_object_domain_identity: String,
    #[allow(dead_code)]
    final_volume_or_mount_identity: String,
    #[allow(dead_code)]
    revalidation_digest: String,
    #[allow(dead_code)]
    one_shot_nonce: String,
    consumed: AtomicBool,
}

impl PreflightPermit {
    pub(crate) fn issue(
        plan: &DeletionPlan,
        authorization: &ExecutionAuthorization,
        request: PreflightPermitRequest,
        clock: &dyn Clock,
    ) -> Result<Self, PreflightPermitError> {
        authorization
            .matches_plan(plan, clock)
            .map_err(PreflightPermitError::AuthorizationMismatch)?;

        let matched_item = plan.exact_item(&request.expected_item_id).ok_or_else(|| {
            PreflightPermitError::PlanItemNotFound {
                item_id: request.expected_item_id.clone(),
            }
        })?;
        let matched_action = matched_item
            .actions
            .iter()
            .find(|action| action.action_id == request.expected_action_id)
            .ok_or_else(|| PreflightPermitError::PlanActionNotFound {
                action_id: request.expected_action_id.clone(),
            })?;
        let risk_tier = matched_action.risk_tier;

        if plan.mode == DeletionMode::Permanent && risk_tier != RiskTier::R4 {
            return Err(PreflightPermitError::PermanentRequiresR4);
        }

        let validated_at = clock.now();
        let expires_at = validated_at
            .checked_add(PERMIT_TTL)
            .ok_or(PreflightPermitError::InvalidClock)?;

        Ok(Self {
            plan_id: plan.plan_id.as_str().to_string(),
            item_id: request.expected_item_id,
            action_id: request.expected_action_id,
            plan_digest: plan.canonical_digest.clone(),
            authorization_id: authorization.authorization_id().to_string(),
            mode: plan.mode,
            risk_tier,
            policy_version: plan.safety_policy_version.clone(),
            policy_digest: plan.safety_policy_digest.clone(),
            protected_anchor_snapshot_digest: plan.protected_anchor_snapshot_digest.clone(),
            validated_at,
            expires_at,
            final_parent_identity: request.final_parent_identity,
            final_object_identity: request.final_object_identity,
            final_filesystem_object_domain_identity: request
                .final_filesystem_object_domain_identity,
            final_volume_or_mount_identity: request.final_volume_or_mount_identity,
            revalidation_digest: request.revalidation_digest,
            one_shot_nonce: request.one_shot_nonce,
            consumed: AtomicBool::new(false),
        })
    }

    pub fn plan_digest(&self) -> &PlanDigest {
        &self.plan_digest
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        now > self.expires_at
    }

    pub(crate) fn consume(&self, clock: &dyn Clock) -> Result<(), PreflightPermitError> {
        if self.is_expired_at(clock.now()) {
            return Err(PreflightPermitError::Expired);
        }

        if self.consumed.swap(true, Ordering::AcqRel) {
            return Err(PreflightPermitError::AlreadyConsumed);
        }

        Ok(())
    }
}

pub fn issue_preflight_permit(
    plan: &DeletionPlan,
    authorization: &ExecutionAuthorization,
    request: PreflightPermitRequest,
    clock: &dyn Clock,
) -> Result<PreflightPermit, PreflightPermitError> {
    PreflightPermit::issue(plan, authorization, request, clock)
}

pub fn consume_preflight_permit(
    permit: &PreflightPermit,
    clock: &dyn Clock,
) -> Result<(), PreflightPermitError> {
    permit.consume(clock)
}

#[derive(Debug, Error)]
pub enum PreflightPermitError {
    #[error("authorization does not bind to the exact plan: {0}")]
    AuthorizationMismatch(AuthorizationMatchError),
    #[error("requested item {item_id} is not part of the exact plan")]
    PlanItemNotFound { item_id: String },
    #[error("requested action {action_id} is not part of the exact plan item")]
    PlanActionNotFound { action_id: String },
    #[error("permit ttl cannot be represented by the current clock")]
    InvalidClock,
    #[error("permanent mode permits require R4 risk")]
    PermanentRequiresR4,
    #[error("permit has expired")]
    Expired,
    #[error("permit has already been consumed")]
    AlreadyConsumed,
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::authorization::PermanentAuthorizationRequest;
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
    fn permit_is_one_shot() {
        let plan = permanent_plan();
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let auth = PermanentAuthorizationRequest {
            authorization_id: "auth-1".to_string(),
            workflow_session: "workflow-1".to_string(),
            nonce: "nonce-auth".to_string(),
        }
        .bind_to_plan(&plan, "user-1", "host-1", &clock)
        .unwrap()
        .claim(7)
        .unwrap();

        let permit = issue_preflight_permit(
            &plan,
            &auth,
            PreflightPermitRequest {
                expected_item_id: "item-1".to_string(),
                expected_action_id: "action-1".to_string(),
                revalidation_digest: "reval-1".to_string(),
                final_parent_identity: "parent-1".to_string(),
                final_object_identity: "object-1".to_string(),
                final_filesystem_object_domain_identity: "domain-1".to_string(),
                final_volume_or_mount_identity: "mount-1".to_string(),
                one_shot_nonce: "permit-1".to_string(),
            },
            &clock,
        )
        .unwrap();

        consume_preflight_permit(&permit, &clock).unwrap();
        assert!(matches!(
            consume_preflight_permit(&permit, &clock).unwrap_err(),
            PreflightPermitError::AlreadyConsumed
        ));
    }

    #[test]
    fn permit_ttl_is_enforced() {
        let plan = permanent_plan();
        let issue_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let auth = PermanentAuthorizationRequest {
            authorization_id: "auth-1".to_string(),
            workflow_session: "workflow-1".to_string(),
            nonce: "nonce-auth".to_string(),
        }
        .bind_to_plan(&plan, "user-1", "host-1", &issue_clock)
        .unwrap()
        .claim(9)
        .unwrap();

        let permit = issue_preflight_permit(
            &plan,
            &auth,
            PreflightPermitRequest {
                expected_item_id: "item-1".to_string(),
                expected_action_id: "action-1".to_string(),
                revalidation_digest: "reval-1".to_string(),
                final_parent_identity: "parent-1".to_string(),
                final_object_identity: "object-1".to_string(),
                final_filesystem_object_domain_identity: "domain-1".to_string(),
                final_volume_or_mount_identity: "mount-1".to_string(),
                one_shot_nonce: "permit-1".to_string(),
            },
            &issue_clock,
        )
        .unwrap();

        let expired_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(13));
        assert!(matches!(
            consume_preflight_permit(&permit, &expired_clock).unwrap_err(),
            PreflightPermitError::Expired
        ));
    }

    #[test]
    fn permit_rejects_mismatched_action_request() {
        let plan = permanent_plan();
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let auth = PermanentAuthorizationRequest {
            authorization_id: "auth-1".to_string(),
            workflow_session: "workflow-1".to_string(),
            nonce: "nonce-auth".to_string(),
        }
        .bind_to_plan(&plan, "user-1", "host-1", &clock)
        .unwrap()
        .claim(11)
        .unwrap();

        let error = issue_preflight_permit(
            &plan,
            &auth,
            PreflightPermitRequest {
                expected_item_id: "item-1".to_string(),
                expected_action_id: "action-missing".to_string(),
                revalidation_digest: "reval-1".to_string(),
                final_parent_identity: "parent-1".to_string(),
                final_object_identity: "object-1".to_string(),
                final_filesystem_object_domain_identity: "domain-1".to_string(),
                final_volume_or_mount_identity: "mount-1".to_string(),
                one_shot_nonce: "permit-1".to_string(),
            },
            &clock,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PreflightPermitError::PlanActionNotFound { action_id } if action_id == "action-missing"
        ));
    }
}
