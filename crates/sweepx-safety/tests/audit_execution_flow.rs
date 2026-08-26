use std::time::{Duration, UNIX_EPOCH};

use sweepx_audit::{
    ActionId, AuditError, AuditStore, AuthorizationSource, BatchId, DigestString, IntentRequest,
    IntentReservation, ItemId, Observation, PathHash, RegisterAuthorization, RequestedMode,
    RiskTier as AuditRiskTier, SessionId, SimulatedOutcome,
};
use sweepx_safety::simulation::{
    DeterministicRevalidationObserver, SimulatedAuthorizationRequest,
    issue_simulated_preflight_permit, verify_simulated_revalidation,
};
use sweepx_safety::{
    AuditBindingError, DeletionMode, DeletionPlan, DeletionPlanInput, ExecutionAuthorization,
    ExplanationDigest, FixedClock, ManifestDigest, PlanAction, PlanId, PlanItemInput,
    PreflightPermitError, RiskFactor, RiskTier, TargetIdentity, consume_preflight_permit,
};
use tempfile::TempDir;

const HOST_ID: &str = "host-p3-integration";
const USER_ID: &str = "user-p3-integration";
const SESSION_ID: &str = "session-p3-integration";

macro_rules! assert_not_impl {
    ($type:ty: $trait:path) => {
        const _: fn() = || {
            struct Implemented;

            trait AmbiguousIfImplemented<Marker> {
                fn marker() {}
            }

            impl<T: ?Sized> AmbiguousIfImplemented<()> for T {}
            impl<T: ?Sized + $trait> AmbiguousIfImplemented<Implemented> for T {}

            let _ = <$type as AmbiguousIfImplemented<_>>::marker;
        };
    };
}

assert_not_impl!(sweepx_audit::DurableIntentToken: Clone);
assert_not_impl!(sweepx_audit::DurableIntentToken: serde::de::DeserializeOwned);
assert_not_impl!(ExecutionAuthorization: Clone);
assert_not_impl!(ExecutionAuthorization: serde::de::DeserializeOwned);

fn item(
    item_id: &str,
    top_level_action_id: &str,
    risk_tier: RiskTier,
    action_ids: &[&str],
) -> PlanItemInput {
    PlanItemInput {
        item_id: item_id.to_string(),
        candidate_id: format!("candidate-{item_id}"),
        explanation_digest: ExplanationDigest::new(format!("explanation-{item_id}")),
        top_level_action_id: top_level_action_id.to_string(),
        target: TargetIdentity::new(format!("target-{item_id}")),
        risk_tier,
        risk_factors: vec![RiskFactor::new(format!("risk-{item_id}"))],
        subtree_complete: true,
        descendant_manifest_digest: Some(ManifestDigest::new(format!("manifest-{item_id}"))),
        actions: action_ids
            .iter()
            .map(|action_id| PlanAction::new(*action_id, risk_tier))
            .collect(),
    }
}

fn plan(items: Vec<PlanItemInput>) -> DeletionPlan {
    DeletionPlan::from_input(DeletionPlanInput {
        plan_id: PlanId::new("plan-p3-integration"),
        nonce: "plan-nonce-p3-integration".to_string(),
        created_at: UNIX_EPOCH + Duration::from_secs(1),
        host_instance_id: HOST_ID.to_string(),
        user_identity: USER_ID.to_string(),
        scan_id: "scan-p3-integration".to_string(),
        scan_root_identity: "root-p3-integration".to_string(),
        mode: DeletionMode::Trash,
        candidate_version: "candidate-v1".to_string(),
        scanner_version: "scanner-v1".to_string(),
        safety_policy_version: "policy-v1".to_string(),
        safety_policy_digest: "policy-digest-p3-integration".to_string(),
        protected_anchor_snapshot_digest: "anchors-digest-p3-integration".to_string(),
        adapter_capabilities_digest: "adapter-digest-p3-integration".to_string(),
        cleaner_set_digest: "cleaner-digest-p3-integration".to_string(),
        items,
    })
    .unwrap()
}

fn authorization(
    plan: &DeletionPlan,
    user_identity: &str,
    host_instance_id: &str,
    workflow_session: &str,
) -> ExecutionAuthorization {
    SimulatedAuthorizationRequest::new(
        "simulation-p3-integration",
        workflow_session,
        "simulation-nonce-p3-integration",
    )
    .bind_to_plan(
        plan,
        user_identity,
        host_instance_id,
        &FixedClock::new(UNIX_EPOCH + Duration::from_secs(10)),
    )
    .unwrap()
}

fn expected_ids(values: &[&str]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    values.sort();
    values
}

#[test]
fn audit_binding_preserves_exact_item_action_and_risk_mapping() {
    let plan = plan(vec![
        item(
            "item-alpha-p3",
            "action-alpha-parent",
            RiskTier::R2,
            &["action-alpha-parent"],
        ),
        item(
            "item-beta-p3",
            "action-beta-only",
            RiskTier::R3,
            &["action-beta-only"],
        ),
    ]);
    let binding = authorization(&plan, USER_ID, HOST_ID, SESSION_ID)
        .audit_binding(
            &plan,
            BatchId::new("batch-p3-integration").unwrap(),
            SessionId::new(SESSION_ID).unwrap(),
        )
        .unwrap();

    assert_eq!(
        binding.authorization_source,
        AuthorizationSource::DeterministicSimulation
    );
    assert_eq!(binding.requested_mode, RequestedMode::Trash);
    assert_eq!(binding.action_count, 2);
    assert_eq!(
        binding
            .item_ids
            .iter()
            .map(|id| id.as_str().to_string())
            .collect::<Vec<_>>(),
        expected_ids(&["item-alpha-p3", "item-beta-p3"]),
    );
    assert_eq!(
        binding
            .action_ids
            .iter()
            .map(|id| id.as_str().to_string())
            .collect::<Vec<_>>(),
        expected_ids(&["action-alpha-parent", "action-beta-only",]),
    );

    let expected_mapping = [
        ("action-alpha-parent", "item-alpha-p3", AuditRiskTier::R2),
        ("action-beta-only", "item-beta-p3", AuditRiskTier::R3),
    ];
    for (action_id, item_id, risk) in expected_mapping {
        let action_id = ActionId::new(action_id).unwrap();
        assert_eq!(
            binding.item_by_action.get(&action_id).map(ItemId::as_str),
            Some(item_id),
        );
        assert_eq!(binding.risk_by_action.get(&action_id), Some(&risk));
    }
    assert_eq!(binding.host_instance_id.as_str(), HOST_ID);
    assert_eq!(binding.user_identity.as_str(), USER_ID);
    assert_eq!(binding.workflow_session.as_str(), SESSION_ID);
}

#[test]
fn audit_binding_rejects_mismatched_principal_host_and_workflow() {
    let plan = plan(vec![item(
        "item-mismatch-p3",
        "action-mismatch-p3",
        RiskTier::R2,
        &["action-mismatch-p3"],
    )]);
    let batch_id = || BatchId::new("batch-mismatch-p3").unwrap();
    let session_id = || SessionId::new(SESSION_ID).unwrap();

    let wrong_user = authorization(&plan, "different-user-p3", HOST_ID, SESSION_ID)
        .audit_binding(&plan, batch_id(), session_id())
        .unwrap_err();
    assert!(matches!(
        wrong_user,
        AuditBindingError::PrincipalOrHostMismatch
    ));

    let wrong_host = authorization(&plan, USER_ID, "different-host-p3", SESSION_ID)
        .audit_binding(&plan, batch_id(), session_id())
        .unwrap_err();
    assert!(matches!(
        wrong_host,
        AuditBindingError::PrincipalOrHostMismatch
    ));

    let wrong_session = authorization(&plan, USER_ID, HOST_ID, SESSION_ID)
        .audit_binding(
            &plan,
            batch_id(),
            SessionId::new("different-session-p3").unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        wrong_session,
        AuditBindingError::WorkflowSessionMismatch
    ));
}

#[test]
fn public_api_round_trip_enforces_one_shot_and_conflicting_duplicate_guards() {
    let plan = plan(vec![item(
        "item-round-trip-p3",
        "action-round-trip-p3",
        RiskTier::R2,
        &["action-round-trip-p3"],
    )]);
    let authorization = authorization(&plan, USER_ID, HOST_ID, SESSION_ID);
    let binding = authorization
        .audit_binding(
            &plan,
            BatchId::new("batch-round-trip-p3").unwrap(),
            SessionId::new(SESSION_ID).unwrap(),
        )
        .unwrap();
    let authorization_id = binding.authorization_id.clone();
    let plan_digest = binding.plan_digest.clone();

    let temp = TempDir::new().unwrap();
    let store = AuditStore::open(temp.path().join("audit")).unwrap();
    store
        .register_authorization(RegisterAuthorization { binding })
        .unwrap();
    let claimed = store
        .claim_execution(&authorization_id, &plan_digest)
        .unwrap();
    let authorization = authorization.claim(claimed.fence_epoch()).unwrap();

    let request = || IntentRequest {
        item_id: ItemId::new("item-round-trip-p3").unwrap(),
        action_id: ActionId::new("action-round-trip-p3").unwrap(),
        source_path_hash: PathHash::new("source-path-round-trip-p3").unwrap(),
        before_revalidation_digest: DigestString::new("revalidation-round-trip-p3").unwrap(),
    };
    let durable_intent = store.reserve_intent(&claimed, request()).unwrap();
    assert_eq!(durable_intent.authorization_id(), &authorization_id);
    assert_eq!(durable_intent.plan_digest(), &plan_digest);
    assert_eq!(durable_intent.item_id().as_str(), "item-round-trip-p3");
    assert_eq!(durable_intent.action_id().as_str(), "action-round-trip-p3");
    assert_eq!(durable_intent.fence_epoch(), claimed.fence_epoch());

    let idempotent_retry = store.reserve_intent_once(&claimed, request()).unwrap();
    let IntentReservation::Existing(existing) = idempotent_retry else {
        panic!("expected non-authority existing-intent diagnostic");
    };
    assert_eq!(existing.attempt_id(), durable_intent.attempt_id());

    let conflicting_duplicate = store
        .reserve_intent(
            &claimed,
            IntentRequest {
                source_path_hash: PathHash::new("changed-source-path-round-trip-p3").unwrap(),
                ..request()
            },
        )
        .unwrap_err();
    assert!(matches!(
        conflicting_duplicate,
        AuditError::ActionAlreadyReserved(ref action_id)
            if action_id == "action-round-trip-p3"
    ));

    let proof =
        verify_simulated_revalidation(&DeterministicRevalidationObserver::new(), &durable_intent);
    let clock = FixedClock::new(UNIX_EPOCH + Duration::from_secs(10));
    let permit =
        issue_simulated_preflight_permit(&plan, &authorization, durable_intent, proof, &clock)
            .unwrap();
    let consumed_permit = consume_preflight_permit(&permit, &clock).unwrap();
    consumed_permit.validate_for_submit(&clock).unwrap();
    assert!(matches!(
        consume_preflight_permit(&permit, &clock).unwrap_err(),
        PreflightPermitError::AlreadyConsumed
    ));

    store
        .record_outcome(
            &claimed,
            consumed_permit.durable_intent(),
            SimulatedOutcome::trash_success(
                "adapter-v1",
                UNIX_EPOCH + Duration::from_secs(10),
                UNIX_EPOCH + Duration::from_secs(11),
                Observation {
                    exists: false,
                    identity: None,
                },
                Observation {
                    exists: true,
                    identity: Some("trash-object-round-trip-p3".to_string()),
                },
                Some("trash-locator-round-trip-p3".to_string()),
                "ok",
                vec!["public API round trip".to_string()],
            )
            .unwrap(),
        )
        .unwrap();

    let retry_after_outcome = store.reserve_intent_once(&claimed, request()).unwrap();
    let IntentReservation::Existing(existing) = retry_after_outcome else {
        panic!("expected non-authority existing-intent diagnostic");
    };
    assert_eq!(
        existing.attempt_id(),
        consumed_permit.durable_intent().attempt_id()
    );
    store.consume_execution(&claimed).unwrap();
    let authorization = authorization.consume().unwrap();
    assert!(matches!(
        authorization.state(),
        sweepx_safety::AuthorizationState::Consumed
    ));

    let integrity = store.verify_integrity().unwrap();
    assert_eq!(integrity.latest_sequence, 5);
    assert_eq!(integrity.action_sequence, 2);
    assert!(integrity.latest_digest.is_some());
}
