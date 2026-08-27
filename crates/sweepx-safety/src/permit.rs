use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use sweepx_audit::{DurableIntentToken, RequestedMode, RiskTier as AuditRiskTier};
use thiserror::Error;

use crate::authorization::{AuthorizationMatchError, ExecutionAuthorization};
use crate::plan::{DeletionMode, DeletionPlan, PlanDigest, RiskTier};
use crate::time::Clock;

pub const PERMIT_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
pub struct SimulatedRevalidationProof {
    attempt_id: String,
    batch_id: String,
    authorization_id: String,
    plan_id: String,
    plan_digest: String,
    item_id: String,
    action_id: String,
    mode: DeletionMode,
    risk_tier: RiskTier,
    revalidation_digest: String,
    one_shot_nonce: String,
    source_path_hash: String,
    fence_epoch: u64,
    final_parent_identity: String,
    final_object_identity: String,
    final_filesystem_object_domain_identity: String,
    final_volume_or_mount_identity: String,
}

mod sealed {
    pub trait Sealed {}
}

pub trait SimulatedRevalidationObserver: sealed::Sealed {
    fn final_parent_identity(&self, durable_intent: &DurableIntentToken) -> String;

    fn final_object_identity(&self, durable_intent: &DurableIntentToken) -> String;

    fn final_filesystem_object_domain_identity(
        &self,
        durable_intent: &DurableIntentToken,
    ) -> String;

    fn final_volume_or_mount_identity(&self, durable_intent: &DurableIntentToken) -> String;
}

#[derive(Debug, Default)]
pub struct DeterministicRevalidationObserver;

impl DeterministicRevalidationObserver {
    pub fn new() -> Self {
        Self
    }
}

impl sealed::Sealed for DeterministicRevalidationObserver {}

impl SimulatedRevalidationObserver for DeterministicRevalidationObserver {
    fn final_parent_identity(&self, durable_intent: &DurableIntentToken) -> String {
        simulated_identity("parent", durable_intent)
    }

    fn final_object_identity(&self, durable_intent: &DurableIntentToken) -> String {
        simulated_identity("object", durable_intent)
    }

    fn final_filesystem_object_domain_identity(
        &self,
        durable_intent: &DurableIntentToken,
    ) -> String {
        simulated_identity("domain", durable_intent)
    }

    fn final_volume_or_mount_identity(&self, durable_intent: &DurableIntentToken) -> String {
        simulated_identity("mount", durable_intent)
    }
}

pub fn verify_simulated_revalidation(
    observer: &impl SimulatedRevalidationObserver,
    durable_intent: &DurableIntentToken,
) -> SimulatedRevalidationProof {
    SimulatedRevalidationProof {
        attempt_id: durable_intent.attempt_id().as_str().to_string(),
        batch_id: durable_intent.batch_id().as_str().to_string(),
        authorization_id: durable_intent.authorization_id().as_str().to_string(),
        plan_id: durable_intent.plan_id().as_str().to_string(),
        plan_digest: durable_intent.plan_digest().as_str().to_string(),
        item_id: durable_intent.item_id().as_str().to_string(),
        action_id: durable_intent.action_id().as_str().to_string(),
        mode: deletion_mode(durable_intent.requested_mode()),
        risk_tier: risk_tier(durable_intent.risk_tier()),
        revalidation_digest: durable_intent
            .before_revalidation_digest()
            .as_str()
            .to_string(),
        one_shot_nonce: durable_intent.nonce().as_str().to_string(),
        source_path_hash: durable_intent.source_path_hash().as_str().to_string(),
        fence_epoch: durable_intent.fence_epoch(),
        final_parent_identity: observer.final_parent_identity(durable_intent),
        final_object_identity: observer.final_object_identity(durable_intent),
        final_filesystem_object_domain_identity: observer
            .final_filesystem_object_domain_identity(durable_intent),
        final_volume_or_mount_identity: observer.final_volume_or_mount_identity(durable_intent),
    }
}

fn simulated_identity(label: &str, durable_intent: &DurableIntentToken) -> String {
    format!(
        "simulation:{label}:{}:{}:{}",
        durable_intent.plan_id().as_str(),
        durable_intent.action_id().as_str(),
        durable_intent.nonce().as_str()
    )
}

#[derive(Debug)]
pub struct PreflightPermit {
    plan_id: String,
    item_id: String,
    action_id: String,
    plan_digest: PlanDigest,
    authorization_id: String,
    mode: DeletionMode,
    risk_tier: RiskTier,
    fence_epoch: u64,
    policy_version: String,
    policy_digest: String,
    protected_anchor_snapshot_digest: String,
    validated_at: SystemTime,
    expires_at: SystemTime,
    final_parent_identity: String,
    final_object_identity: String,
    final_filesystem_object_domain_identity: String,
    final_volume_or_mount_identity: String,
    revalidation_digest: String,
    one_shot_nonce: String,
    durable_intent: Mutex<Option<DurableIntentToken>>,
    consumed: AtomicBool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumedPreflightPermit {
    Trash(ConsumedTrashPreflightPermit),
    Permanent(ConsumedPermanentPreflightPermit),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConsumedTrashPreflightPermit {
    claims: ConsumedPermitClaims,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConsumedPermanentPreflightPermit {
    claims: ConsumedPermitClaims,
}

#[derive(Debug, PartialEq, Eq)]
struct ConsumedPermitClaims {
    plan_id: String,
    item_id: String,
    action_id: String,
    plan_digest: PlanDigest,
    authorization_id: String,
    mode: DeletionMode,
    risk_tier: RiskTier,
    fence_epoch: u64,
    validated_at: SystemTime,
    expires_at: SystemTime,
    policy_version: String,
    policy_digest: String,
    protected_anchor_snapshot_digest: String,
    final_parent_identity: String,
    final_object_identity: String,
    final_filesystem_object_domain_identity: String,
    final_volume_or_mount_identity: String,
    revalidation_digest: String,
    one_shot_nonce: String,
    durable_intent: DurableIntentToken,
}

impl PreflightPermit {
    pub(crate) fn issue(
        plan: &DeletionPlan,
        authorization: &ExecutionAuthorization,
        durable_intent: DurableIntentToken,
        revalidation: SimulatedRevalidationProof,
        clock: &dyn Clock,
    ) -> Result<Self, PreflightPermitError> {
        if !authorization.is_deterministic_simulation() {
            return Err(PreflightPermitError::SimulationAuthorizationRequired);
        }
        durable_intent
            .validate_current_process()
            .map_err(map_intent_authority_error)?;
        authorization
            .matches_plan(plan, clock)
            .map_err(PreflightPermitError::AuthorizationMismatch)?;

        let authorization_id = durable_intent.authorization_id().as_str().to_string();
        let attempt_id = durable_intent.attempt_id().as_str();
        let batch_id = durable_intent.batch_id().as_str();
        let plan_id = durable_intent.plan_id().as_str().to_string();
        let plan_digest = durable_intent.plan_digest().as_str().to_string();
        let item_id = durable_intent.item_id().as_str().to_string();
        let action_id = durable_intent.action_id().as_str().to_string();
        let mode = deletion_mode(durable_intent.requested_mode());
        let audit_risk_tier = risk_tier(durable_intent.risk_tier());
        let fence_epoch = durable_intent.fence_epoch();
        let revalidation_digest = durable_intent
            .before_revalidation_digest()
            .as_str()
            .to_string();
        let one_shot_nonce = durable_intent.nonce().as_str().to_string();
        let source_path_hash = durable_intent.source_path_hash().as_str();

        let authorization_fence_epoch = authorization
            .fence_epoch()
            .map_err(PreflightPermitError::AuthorizationMismatch)?;
        if authorization_id != authorization.authorization_id()
            || plan_id != plan.plan_id.as_str()
            || plan_digest != plan.canonical_digest.as_str()
            || mode != plan.mode
            || fence_epoch != authorization_fence_epoch
            || revalidation.attempt_id != attempt_id
            || revalidation.batch_id != batch_id
            || revalidation.authorization_id != authorization_id
            || revalidation.plan_id != plan_id
            || revalidation.plan_digest != plan_digest
            || revalidation.item_id != item_id
            || revalidation.action_id != action_id
            || revalidation.mode != mode
            || revalidation.risk_tier != audit_risk_tier
            || revalidation.revalidation_digest != revalidation_digest
            || revalidation.one_shot_nonce != one_shot_nonce
            || revalidation.source_path_hash != source_path_hash
            || revalidation.fence_epoch != fence_epoch
        {
            return Err(PreflightPermitError::IntentOrRevalidationMismatch);
        }

        let matched_item =
            plan.exact_item(&item_id)
                .ok_or_else(|| PreflightPermitError::PlanItemNotFound {
                    item_id: item_id.clone(),
                })?;
        let matched_action = matched_item
            .actions
            .iter()
            .find(|action| action.action_id == action_id)
            .ok_or_else(|| PreflightPermitError::PlanActionNotFound {
                action_id: action_id.clone(),
            })?;
        if audit_risk_tier != matched_action.risk_tier {
            return Err(PreflightPermitError::IntentOrRevalidationMismatch);
        }

        if mode == DeletionMode::Permanent && audit_risk_tier != RiskTier::R4 {
            return Err(PreflightPermitError::PermanentRequiresR4);
        }

        let validated_at = clock.now();
        let expires_at = validated_at
            .checked_add(PERMIT_TTL)
            .ok_or(PreflightPermitError::InvalidClock)?;

        Ok(Self {
            plan_id,
            item_id,
            action_id,
            plan_digest: PlanDigest::new(plan_digest),
            authorization_id,
            mode,
            risk_tier: audit_risk_tier,
            fence_epoch,
            policy_version: plan.safety_policy_version.clone(),
            policy_digest: plan.safety_policy_digest.clone(),
            protected_anchor_snapshot_digest: plan.protected_anchor_snapshot_digest.clone(),
            validated_at,
            expires_at,
            final_parent_identity: revalidation.final_parent_identity,
            final_object_identity: revalidation.final_object_identity,
            final_filesystem_object_domain_identity: revalidation
                .final_filesystem_object_domain_identity,
            final_volume_or_mount_identity: revalidation.final_volume_or_mount_identity,
            revalidation_digest,
            one_shot_nonce,
            durable_intent: Mutex::new(Some(durable_intent)),
            consumed: AtomicBool::new(false),
        })
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    pub(crate) fn consume(
        &self,
        clock: &dyn Clock,
    ) -> Result<ConsumedPreflightPermit, PreflightPermitError> {
        if self.consumed.swap(true, Ordering::AcqRel) {
            return Err(PreflightPermitError::AlreadyConsumed);
        }

        let mut durable_intent = self
            .durable_intent
            .lock()
            .map_err(|_| PreflightPermitError::AuthorityStateUnavailable)?;
        durable_intent
            .as_ref()
            .ok_or(PreflightPermitError::AuthorityStateUnavailable)?
            .validate_current_process()
            .map_err(map_intent_authority_error)?;
        let durable_intent = durable_intent
            .take()
            .ok_or(PreflightPermitError::AuthorityStateUnavailable)?;

        let now = clock.now();
        if self.is_expired_at(now) {
            return Err(PreflightPermitError::ExpiredAfterConsumption);
        }

        let claims = ConsumedPermitClaims {
            plan_id: self.plan_id.clone(),
            item_id: self.item_id.clone(),
            action_id: self.action_id.clone(),
            plan_digest: self.plan_digest.clone(),
            authorization_id: self.authorization_id.clone(),
            mode: self.mode,
            risk_tier: self.risk_tier,
            fence_epoch: self.fence_epoch,
            validated_at: self.validated_at,
            expires_at: self.expires_at,
            policy_version: self.policy_version.clone(),
            policy_digest: self.policy_digest.clone(),
            protected_anchor_snapshot_digest: self.protected_anchor_snapshot_digest.clone(),
            final_parent_identity: self.final_parent_identity.clone(),
            final_object_identity: self.final_object_identity.clone(),
            final_filesystem_object_domain_identity: self
                .final_filesystem_object_domain_identity
                .clone(),
            final_volume_or_mount_identity: self.final_volume_or_mount_identity.clone(),
            revalidation_digest: self.revalidation_digest.clone(),
            one_shot_nonce: self.one_shot_nonce.clone(),
            durable_intent,
        };

        Ok(match self.mode {
            DeletionMode::Trash => {
                ConsumedPreflightPermit::Trash(ConsumedTrashPreflightPermit { claims })
            }
            DeletionMode::Permanent => {
                ConsumedPreflightPermit::Permanent(ConsumedPermanentPreflightPermit { claims })
            }
        })
    }
}

fn deletion_mode(mode: RequestedMode) -> DeletionMode {
    match mode {
        RequestedMode::Trash => DeletionMode::Trash,
        RequestedMode::Permanent => DeletionMode::Permanent,
    }
}

fn risk_tier(risk: AuditRiskTier) -> RiskTier {
    match risk {
        AuditRiskTier::R1 => RiskTier::R1,
        AuditRiskTier::R2 => RiskTier::R2,
        AuditRiskTier::R3 => RiskTier::R3,
        AuditRiskTier::R4 => RiskTier::R4,
    }
}

impl ConsumedPermitClaims {
    fn validate_not_expired_at_submit(&self, now: SystemTime) -> Result<(), PreflightPermitError> {
        self.durable_intent
            .validate_current_process()
            .map_err(map_intent_authority_error)?;
        if now >= self.expires_at {
            return Err(PreflightPermitError::ExpiredAtSubmit);
        }
        Ok(())
    }
}

fn map_intent_authority_error(error: sweepx_audit::AuditError) -> PreflightPermitError {
    match error {
        sweepx_audit::AuditError::ForkedProcess => PreflightPermitError::ForkedProcess,
        _ => PreflightPermitError::AuthorityStateUnavailable,
    }
}

macro_rules! impl_consumed_permit {
    ($permit:ty) => {
        impl $permit {
            pub fn validate_for_submit(
                &self,
                clock: &dyn Clock,
            ) -> Result<(), PreflightPermitError> {
                self.claims.validate_not_expired_at_submit(clock.now())
            }

            pub fn durable_intent(&self) -> &DurableIntentToken {
                &self.claims.durable_intent
            }

            pub fn authorization_id(&self) -> &str {
                &self.claims.authorization_id
            }

            pub fn plan_id(&self) -> &str {
                &self.claims.plan_id
            }

            pub fn plan_digest(&self) -> &PlanDigest {
                &self.claims.plan_digest
            }

            pub fn item_id(&self) -> &str {
                &self.claims.item_id
            }

            pub fn action_id(&self) -> &str {
                &self.claims.action_id
            }

            pub fn mode(&self) -> DeletionMode {
                self.claims.mode
            }

            pub fn risk_tier(&self) -> RiskTier {
                self.claims.risk_tier
            }

            pub fn fence_epoch(&self) -> u64 {
                self.claims.fence_epoch
            }

            pub fn validated_at(&self) -> SystemTime {
                self.claims.validated_at
            }

            pub fn expires_at(&self) -> SystemTime {
                self.claims.expires_at
            }

            pub fn policy_version(&self) -> &str {
                &self.claims.policy_version
            }

            pub fn policy_digest(&self) -> &str {
                &self.claims.policy_digest
            }

            pub fn protected_anchor_snapshot_digest(&self) -> &str {
                &self.claims.protected_anchor_snapshot_digest
            }

            pub fn final_parent_identity(&self) -> &str {
                &self.claims.final_parent_identity
            }

            pub fn final_object_identity(&self) -> &str {
                &self.claims.final_object_identity
            }

            pub fn final_filesystem_object_domain_identity(&self) -> &str {
                &self.claims.final_filesystem_object_domain_identity
            }

            pub fn final_volume_or_mount_identity(&self) -> &str {
                &self.claims.final_volume_or_mount_identity
            }

            pub fn revalidation_digest(&self) -> &str {
                &self.claims.revalidation_digest
            }

            pub fn one_shot_nonce(&self) -> &str {
                &self.claims.one_shot_nonce
            }
        }
    };
}

impl_consumed_permit!(ConsumedTrashPreflightPermit);
impl_consumed_permit!(ConsumedPermanentPreflightPermit);

impl ConsumedPreflightPermit {
    pub fn validate_for_submit(&self, clock: &dyn Clock) -> Result<(), PreflightPermitError> {
        match self {
            Self::Trash(permit) => permit.validate_for_submit(clock),
            Self::Permanent(permit) => permit.validate_for_submit(clock),
        }
    }

    pub fn durable_intent(&self) -> &DurableIntentToken {
        match self {
            Self::Trash(permit) => permit.durable_intent(),
            Self::Permanent(permit) => permit.durable_intent(),
        }
    }
}

pub fn issue_simulated_preflight_permit(
    plan: &DeletionPlan,
    authorization: &ExecutionAuthorization,
    durable_intent: DurableIntentToken,
    revalidation: SimulatedRevalidationProof,
    clock: &dyn Clock,
) -> Result<PreflightPermit, PreflightPermitError> {
    PreflightPermit::issue(plan, authorization, durable_intent, revalidation, clock)
}

pub fn consume_preflight_permit(
    permit: &PreflightPermit,
    clock: &dyn Clock,
) -> Result<ConsumedPreflightPermit, PreflightPermitError> {
    permit.consume(clock)
}

#[derive(Debug, Error)]
pub enum PreflightPermitError {
    #[error("simulation permit issuance requires deterministic-simulation authorization")]
    SimulationAuthorizationRequired,
    #[error("authorization does not bind to the exact plan: {0}")]
    AuthorizationMismatch(AuthorizationMatchError),
    #[error(
        "simulation-only permit issuance requires exactly matching intent and revalidation authority"
    )]
    IntentOrRevalidationMismatch,
    #[error("requested item {item_id} is not part of the exact plan")]
    PlanItemNotFound { item_id: String },
    #[error("requested action {action_id} is not part of the exact plan item")]
    PlanActionNotFound { action_id: String },
    #[error("permit ttl cannot be represented by the current clock")]
    InvalidClock,
    #[error("permanent mode permits require R4 risk")]
    PermanentRequiresR4,
    #[error("permit expired after being atomically consumed; authority remains spent")]
    ExpiredAfterConsumption,
    #[error("consumed permit expired before adapter submit")]
    ExpiredAtSubmit,
    #[error("permit has already been consumed")]
    AlreadyConsumed,
    #[error("permit authority state is unavailable and remains spent")]
    AuthorityStateUnavailable,
    #[error("permit authority belongs to a different process")]
    ForkedProcess,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::{Duration, UNIX_EPOCH};

    use sweepx_audit::{
        ActionId, AuditStore, AuthorizationBinding, AuthorizationId, AuthorizationSource, BatchId,
        DigestString, HostId, IntentRequest, ItemId, Observation, PathHash, PlanId as AuditPlanId,
        RegisterAuthorization, RequestedMode, RiskTier as AuditRiskTier, SessionId,
        SimulatedOutcome, UserId,
    };
    use tempfile::TempDir;

    use crate::authorization::SimulatedAuthorizationRequest;
    use crate::plan::{
        DeletionPlanInput, ExplanationDigest, ManifestDigest, PlanAction, PlanId, PlanItemInput,
        RiskFactor, TargetIdentity,
    };
    use crate::time::FixedClock;

    use super::*;

    const ITEM_ID: &str = "item-01-safety";
    const ACTION_ID: &str = "action-01-safety";
    const REVALIDATION_DIGEST: &str = "revalidation-01-safety";

    struct Fixture {
        _temp: TempDir,
        store: AuditStore,
        plan: DeletionPlan,
        authorization: ExecutionAuthorization,
        claimed: sweepx_audit::ClaimedExecution,
    }

    fn plan(mode: DeletionMode, risk: RiskTier, plan_id: &str) -> DeletionPlan {
        DeletionPlan::from_input(DeletionPlanInput {
            plan_id: PlanId::new(plan_id),
            nonce: "nonce-plan-safety".to_string(),
            created_at: UNIX_EPOCH + Duration::from_secs(1),
            host_instance_id: "host-01-safety".to_string(),
            user_identity: "user-01-safety".to_string(),
            scan_id: "scan-01-safety".to_string(),
            scan_root_identity: "root-01-safety".to_string(),
            mode,
            candidate_version: "candidate-v1".to_string(),
            scanner_version: "scanner-v1".to_string(),
            safety_policy_version: "policy-v1".to_string(),
            safety_policy_digest: "policy-digest-safety".to_string(),
            protected_anchor_snapshot_digest: "anchors-digest-safety".to_string(),
            adapter_capabilities_digest: "adapter-digest-safety".to_string(),
            cleaner_set_digest: "cleaner-digest-safety".to_string(),
            items: vec![PlanItemInput {
                item_id: ITEM_ID.to_string(),
                candidate_id: "candidate-01-safety".to_string(),
                explanation_digest: ExplanationDigest::new("explanation-01-safety"),
                top_level_action_id: ACTION_ID.to_string(),
                target: TargetIdentity::new("target-01-safety"),
                native_target: None,
                risk_tier: risk,
                risk_factors: vec![RiskFactor::new("risk-safety")],
                subtree_complete: true,
                descendant_manifest_digest: Some(ManifestDigest::new("manifest-01-safety")),
                actions: vec![
                    PlanAction::new(ACTION_ID, risk)
                        .with_manifest_digest(ManifestDigest::new("manifest-01-safety")),
                ],
            }],
        })
        .unwrap()
    }

    fn fixture(mode: DeletionMode, risk: RiskTier, suffix: &str) -> Fixture {
        let plan_id = format!("plan-{suffix}-safety");
        let authorization_id = format!("auth-{suffix}-safety");
        let plan = plan(mode, risk, &plan_id);
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let unclaimed = SimulatedAuthorizationRequest::new(
            authorization_id.clone(),
            format!("session-{suffix}-safety"),
            format!("simulation-nonce-{suffix}"),
        )
        .bind_to_plan(&plan, "user-01-safety", "host-01-safety", &clock)
        .unwrap();

        let temp = TempDir::new().unwrap();
        let store = AuditStore::open(temp.path().join("audit")).unwrap();
        let audit_mode = match mode {
            DeletionMode::Trash => RequestedMode::Trash,
            DeletionMode::Permanent => RequestedMode::Permanent,
        };
        let audit_risk = match risk {
            RiskTier::R1 => AuditRiskTier::R1,
            RiskTier::R2 => AuditRiskTier::R2,
            RiskTier::R3 => AuditRiskTier::R3,
            RiskTier::R4 => AuditRiskTier::R4,
            RiskTier::Blocked => panic!("blocked risk cannot produce an executable fixture"),
        };
        let audit_authorization_id = AuthorizationId::new(authorization_id).unwrap();
        let audit_plan_digest =
            DigestString::new(plan.canonical_digest.as_str().to_string()).unwrap();
        let audit_item_id = ItemId::new(ITEM_ID).unwrap();
        let audit_action_id = ActionId::new(ACTION_ID).unwrap();
        let mut item_ids = BTreeSet::new();
        item_ids.insert(audit_item_id.clone());
        let mut action_ids = BTreeSet::new();
        action_ids.insert(audit_action_id.clone());
        let mut risk_by_action = BTreeMap::new();
        risk_by_action.insert(audit_action_id.clone(), audit_risk);
        let mut item_by_action = BTreeMap::new();
        item_by_action.insert(audit_action_id, audit_item_id.clone());
        let binding = AuthorizationBinding {
            authorization_id: audit_authorization_id.clone(),
            authorization_source: AuthorizationSource::DeterministicSimulation,
            batch_id: BatchId::new(format!("batch-{suffix}-safety")).unwrap(),
            plan_id: AuditPlanId::new(plan_id).unwrap(),
            plan_digest: audit_plan_digest.clone(),
            requested_mode: audit_mode,
            item_ids,
            action_ids,
            item_by_action,
            action_count: 1,
            risk_by_action,
            policy_version: "policy-v1".to_string(),
            policy_digest: DigestString::new("policy-digest-safety").unwrap(),
            protected_anchor_snapshot_digest: DigestString::new("anchors-digest-safety").unwrap(),
            adapter_capabilities_digest: DigestString::new("adapter-digest-safety").unwrap(),
            cleaner_set_digest: DigestString::new("cleaner-digest-safety").unwrap(),
            host_instance_id: HostId::new("host-01-safety").unwrap(),
            user_identity: UserId::new("user-01-safety").unwrap(),
            workflow_session: SessionId::new(format!("session-{suffix}-safety")).unwrap(),
        };
        store
            .register_authorization(RegisterAuthorization { binding })
            .unwrap();
        let claimed = store
            .claim_execution(&audit_authorization_id, &audit_plan_digest)
            .unwrap();
        let authorization = unclaimed.claim(claimed.fence_epoch()).unwrap();

        Fixture {
            _temp: temp,
            store,
            plan,
            authorization,
            claimed,
        }
    }

    fn reserve_intent(fixture: &Fixture) -> DurableIntentToken {
        fixture
            .store
            .reserve_intent(
                &fixture.claimed,
                IntentRequest {
                    item_id: ItemId::new(ITEM_ID).unwrap(),
                    action_id: ActionId::new(ACTION_ID).unwrap(),
                    source_path_hash: PathHash::new("source-path-01-safety").unwrap(),
                    before_revalidation_digest: DigestString::new(REVALIDATION_DIGEST).unwrap(),
                },
            )
            .unwrap()
    }

    fn issue(fixture: &Fixture, clock: &FixedClock) -> PreflightPermit {
        let durable_intent = reserve_intent(fixture);
        let revalidation = verify_simulated_revalidation(
            &DeterministicRevalidationObserver::new(),
            &durable_intent,
        );
        issue_simulated_preflight_permit(
            &fixture.plan,
            &fixture.authorization,
            durable_intent,
            revalidation,
            clock,
        )
        .unwrap()
    }

    #[test]
    fn permit_is_one_shot_and_retains_real_durable_intent() {
        let fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "one-shot");
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let durable_intent = reserve_intent(&fixture);
        let expected_attempt_id = durable_intent.attempt_id().as_str().to_string();
        let revalidation = verify_simulated_revalidation(
            &DeterministicRevalidationObserver::new(),
            &durable_intent,
        );
        let permit = issue_simulated_preflight_permit(
            &fixture.plan,
            &fixture.authorization,
            durable_intent,
            revalidation,
            &clock,
        )
        .unwrap();

        let consumed = consume_preflight_permit(&permit, &clock).unwrap();
        let ConsumedPreflightPermit::Permanent(consumed) = consumed else {
            panic!("expected permanent permit");
        };
        assert_eq!(consumed.plan_id(), fixture.plan.plan_id.as_str());
        assert_eq!(
            consumed.authorization_id(),
            fixture.authorization.authorization_id()
        );
        assert_eq!(consumed.item_id(), ITEM_ID);
        assert_eq!(consumed.action_id(), ACTION_ID);
        assert_eq!(consumed.mode(), DeletionMode::Permanent);
        assert_eq!(consumed.risk_tier(), RiskTier::R4);
        assert_eq!(consumed.fence_epoch(), fixture.claimed.fence_epoch());
        assert_eq!(consumed.revalidation_digest(), REVALIDATION_DIGEST);
        assert_eq!(
            consumed.one_shot_nonce(),
            consumed.durable_intent().nonce().as_str()
        );
        assert_eq!(
            consumed.durable_intent().attempt_id().as_str(),
            expected_attempt_id
        );
        // Registration, claim, and intent are all part of the same durable hash chain.
        assert_eq!(fixture.store.verify_integrity().unwrap().latest_sequence, 3);
        fixture
            .store
            .record_outcome(
                &fixture.claimed,
                consumed.durable_intent(),
                SimulatedOutcome::permanent_success(
                    "adapter-v1",
                    UNIX_EPOCH + Duration::from_secs(10),
                    UNIX_EPOCH + Duration::from_secs(11),
                    Observation {
                        exists: false,
                        identity: None,
                    },
                    "ok",
                    vec![],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(fixture.store.verify_integrity().unwrap().latest_sequence, 4);
        assert!(matches!(
            consumed.validate_for_submit(&clock),
            Err(PreflightPermitError::AuthorityStateUnavailable)
        ));
        assert!(matches!(
            consume_preflight_permit(&permit, &clock).unwrap_err(),
            PreflightPermitError::AlreadyConsumed
        ));
    }

    #[test]
    fn trash_intent_yields_only_a_trash_consumed_permit() {
        let fixture = fixture(DeletionMode::Trash, RiskTier::R2, "trash-mode");
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let permit = issue(&fixture, &clock);
        let consumed = consume_preflight_permit(&permit, &clock).unwrap();

        let ConsumedPreflightPermit::Trash(consumed) = consumed else {
            panic!("expected trash permit");
        };
        assert_eq!(consumed.mode(), DeletionMode::Trash);
        assert_eq!(consumed.risk_tier(), RiskTier::R2);
        assert_eq!(
            consumed.durable_intent().requested_mode(),
            RequestedMode::Trash
        );
    }

    #[test]
    fn durable_intent_must_match_plan_and_authorization_exactly() {
        let source = fixture(DeletionMode::Permanent, RiskTier::R4, "mismatch-source");
        let target = fixture(DeletionMode::Permanent, RiskTier::R4, "mismatch-target");
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let durable_intent = reserve_intent(&source);
        let revalidation = verify_simulated_revalidation(
            &DeterministicRevalidationObserver::new(),
            &durable_intent,
        );

        let error = issue_simulated_preflight_permit(
            &target.plan,
            &target.authorization,
            durable_intent,
            revalidation,
            &clock,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PreflightPermitError::IntentOrRevalidationMismatch
        ));
    }

    #[test]
    fn revalidation_proof_is_bound_to_the_exact_durable_intent() {
        let first = fixture(DeletionMode::Permanent, RiskTier::R4, "proof-first");
        let second = fixture(DeletionMode::Permanent, RiskTier::R4, "proof-second");
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let first_intent = reserve_intent(&first);
        let first_proof =
            verify_simulated_revalidation(&DeterministicRevalidationObserver::new(), &first_intent);

        let error = issue_simulated_preflight_permit(
            &second.plan,
            &second.authorization,
            reserve_intent(&second),
            first_proof,
            &clock,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PreflightPermitError::IntentOrRevalidationMismatch
        ));
    }

    #[test]
    fn permit_issuance_rejects_non_simulation_authorization() {
        let fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "real-auth-rejected");
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let durable_intent = reserve_intent(&fixture);
        let proof = verify_simulated_revalidation(
            &DeterministicRevalidationObserver::new(),
            &durable_intent,
        );
        let human_authorization = crate::authorization::HumanApprovalRequest {
            approval_id: fixture.authorization.authorization_id().to_string(),
            workflow_session: "session-real-auth-rejected-safety".to_string(),
            nonce: "human-nonce-real-auth-rejected".to_string(),
            confirmation_evidence:
                crate::authorization::ApprovalConfirmationEvidence::NativeFirstPartyLocalModal,
        }
        .bind_to_plan(&fixture.plan, "user-01-safety", "host-01-safety", &clock)
        .unwrap()
        .claim(fixture.claimed.fence_epoch())
        .unwrap();

        assert!(matches!(
            issue_simulated_preflight_permit(
                &fixture.plan,
                &human_authorization,
                durable_intent,
                proof,
                &clock,
            )
            .unwrap_err(),
            PreflightPermitError::SimulationAuthorizationRequired
        ));
    }

    #[test]
    fn permit_ttl_is_enforced_after_atomic_consumption() {
        let fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "consume-expiry");
        let issue_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let permit = issue(&fixture, &issue_clock);
        let expired_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(13));

        assert!(matches!(
            consume_preflight_permit(&permit, &expired_clock).unwrap_err(),
            PreflightPermitError::ExpiredAfterConsumption
        ));
        assert!(matches!(
            consume_preflight_permit(&permit, &issue_clock).unwrap_err(),
            PreflightPermitError::AlreadyConsumed
        ));
    }

    #[test]
    fn permit_expires_at_the_exact_ttl_boundary_and_stays_spent() {
        let fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "consume-boundary");
        let issue_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let permit = issue(&fixture, &issue_clock);
        let boundary_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(12));

        assert!(matches!(
            consume_preflight_permit(&permit, &boundary_clock).unwrap_err(),
            PreflightPermitError::ExpiredAfterConsumption
        ));
        assert!(matches!(
            consume_preflight_permit(&permit, &issue_clock).unwrap_err(),
            PreflightPermitError::AlreadyConsumed
        ));
    }

    #[test]
    fn consumed_permit_submit_rechecks_ttl() {
        let fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "submit-expiry");
        let issue_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let permit = issue(&fixture, &issue_clock);
        let consumed = consume_preflight_permit(&permit, &issue_clock).unwrap();
        let expired_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(13));

        assert!(matches!(
            consumed.validate_for_submit(&expired_clock).unwrap_err(),
            PreflightPermitError::ExpiredAtSubmit
        ));
    }

    #[test]
    fn consumed_permit_submit_rejects_the_exact_ttl_boundary() {
        let fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "submit-boundary");
        let issue_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let permit = issue(&fixture, &issue_clock);
        let consumed = consume_preflight_permit(&permit, &issue_clock).unwrap();
        let boundary_clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(12));

        assert!(matches!(
            consumed.validate_for_submit(&boundary_clock).unwrap_err(),
            PreflightPermitError::ExpiredAtSubmit
        ));
    }

    #[cfg(unix)]
    #[test]
    fn durable_intent_and_permit_cannot_cross_a_process_fork() {
        use std::os::unix::process::ExitStatusExt;

        let issue_fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "fork-issue");
        let consume_fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "fork-consume");
        let submit_fixture = fixture(DeletionMode::Permanent, RiskTier::R4, "fork-submit");
        let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
        let issue_intent = reserve_intent(&issue_fixture);
        let issue_proof =
            verify_simulated_revalidation(&DeterministicRevalidationObserver::new(), &issue_intent);
        let consume_permit = issue(&consume_fixture, &clock);
        let submit_permit = issue(&submit_fixture, &clock);
        let consumed_submit_permit = consume_preflight_permit(&submit_permit, &clock).unwrap();

        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let issue_rejected = matches!(
                issue_simulated_preflight_permit(
                    &issue_fixture.plan,
                    &issue_fixture.authorization,
                    issue_intent,
                    issue_proof,
                    &clock,
                ),
                Err(PreflightPermitError::ForkedProcess)
            );
            let consume_rejected = matches!(
                consume_preflight_permit(&consume_permit, &clock),
                Err(PreflightPermitError::ForkedProcess)
            );
            let submit_rejected = matches!(
                consumed_submit_permit.validate_for_submit(&clock),
                Err(PreflightPermitError::ForkedProcess)
            );
            unsafe {
                libc::_exit(if issue_rejected && consume_rejected && submit_rejected {
                    0
                } else {
                    1
                })
            };
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(waited, child);
        let status = std::process::ExitStatus::from_raw(status);
        assert!(status.success());

        // The child's copy cannot spend authority held by the parent process.
        assert!(consume_preflight_permit(&consume_permit, &clock).is_ok());
        assert!(consumed_submit_permit.validate_for_submit(&clock).is_ok());
    }
}
