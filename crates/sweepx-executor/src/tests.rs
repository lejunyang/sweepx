use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sweepx_audit::{
    AuditError, AuditStore, AuthorizationId, BatchId, DigestString, IntentRequest,
    PlanId as AuditPlanId, RegisterAuthorization, RequestedMode, RiskTier as AuditRiskTier,
    SessionId,
};
use sweepx_safety::simulation::SimulatedAuthorizationRequest;
use sweepx_safety::{
    DeletionPlanInput, ExplanationDigest, FixedClock, ManifestDigest, PlanAction, PlanId,
    PlanItemInput, RiskFactor, TargetIdentity,
};
use tempfile::TempDir;

use super::*;

fn base_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_000)
}

struct Fixture {
    _temp: TempDir,
    store: AuditStore,
    claimed: ClaimedExecution,
    plan: DeletionPlan,
    authorization: ExecutionAuthorization,
    actions: Vec<ActionRequest>,
    suffix: String,
}

fn plan(mode: DeletionMode, action_count: usize, suffix: &str) -> DeletionPlan {
    let risk = match mode {
        DeletionMode::Trash => RiskTier::R2,
        DeletionMode::Permanent => RiskTier::R4,
    };
    let mut items = (1..=action_count)
        .rev()
        .map(|index| {
            let item_id = format!("item-{index:04}");
            let action_id = format!("action-{index:04}");
            PlanItemInput {
                item_id,
                candidate_id: format!("candidate-{index:04}"),
                explanation_digest: ExplanationDigest::new(format!("explanation-{index:04}")),
                top_level_action_id: action_id.clone(),
                target: TargetIdentity::new(format!("target-{index:04}")),
                risk_tier: risk,
                risk_factors: vec![RiskFactor::new("executor-test")],
                subtree_complete: true,
                descendant_manifest_digest: Some(ManifestDigest::new(format!(
                    "manifest-{index:04}"
                ))),
                actions: vec![
                    PlanAction::new(action_id, risk)
                        .with_manifest_digest(ManifestDigest::new(format!("manifest-{index:04}"))),
                ],
            }
        })
        .collect::<Vec<_>>();
    if items.is_empty() {
        items.push(PlanItemInput {
            item_id: "item-0001".to_string(),
            candidate_id: "candidate-0001".to_string(),
            explanation_digest: ExplanationDigest::new("explanation-0001"),
            top_level_action_id: "action-0001".to_string(),
            target: TargetIdentity::new("target-0001"),
            risk_tier: risk,
            risk_factors: vec![RiskFactor::new("executor-test")],
            subtree_complete: true,
            descendant_manifest_digest: Some(ManifestDigest::new("manifest-0001")),
            actions: vec![
                PlanAction::new("action-0001", risk)
                    .with_manifest_digest(ManifestDigest::new("manifest-0001")),
            ],
        });
    }

    DeletionPlan::from_input(DeletionPlanInput {
        plan_id: PlanId::new(format!("plan-{suffix}-executor")),
        nonce: format!("plan-nonce-{suffix}"),
        created_at: base_time(),
        host_instance_id: "host-executor-01".to_string(),
        user_identity: "user-executor-01".to_string(),
        scan_id: format!("scan-{suffix}-executor"),
        scan_root_identity: "root-executor-01".to_string(),
        mode,
        candidate_version: "candidate-v1".to_string(),
        scanner_version: "scanner-v1".to_string(),
        safety_policy_version: "policy-v1".to_string(),
        safety_policy_digest: "policy-digest-executor".to_string(),
        protected_anchor_snapshot_digest: "anchors-digest-executor".to_string(),
        adapter_capabilities_digest: "adapter-digest-executor".to_string(),
        cleaner_set_digest: "cleaner-digest-executor".to_string(),
        items,
    })
    .unwrap()
}

fn unclaimed_authorization(
    plan: &DeletionPlan,
    _mode: DeletionMode,
    suffix: &str,
    clock: &dyn Clock,
) -> ExecutionAuthorization {
    SimulatedAuthorizationRequest::new(
        format!("simulation-{suffix}-executor"),
        format!("session-{suffix}-executor"),
        format!("simulation-nonce-{suffix}"),
    )
    .bind_to_plan(plan, "user-executor-01", "host-executor-01", clock)
    .unwrap()
}

fn canonical_actions(plan: &DeletionPlan) -> Vec<ActionRequest> {
    plan.ordered_simulated_actions()
        .unwrap()
        .into_iter()
        .map(|action| ActionRequest::new(action.item_id(), action.action_id()))
        .collect()
}

fn derived_action(plan: &DeletionPlan, index: usize) -> (String, String) {
    let action = plan.ordered_simulated_actions().unwrap().remove(index);
    (
        action.source_identity_digest().to_string(),
        action.revalidation_digest().to_string(),
    )
}

fn fixture(mode: DeletionMode, action_count: usize, suffix: &str) -> Fixture {
    let plan = plan(mode, action_count, suffix);
    let clock = FixedClock::new(base_time() + Duration::from_secs(1));
    let unclaimed = unclaimed_authorization(&plan, mode, suffix, &clock);
    let temp = TempDir::new().unwrap();
    let store = AuditStore::open(temp.path().join("audit")).unwrap();
    let batch_id = BatchId::new(format!("batch-{suffix}-executor")).unwrap();
    let session_id = SessionId::new(format!("session-{suffix}-executor")).unwrap();
    let binding = unclaimed
        .audit_binding(&plan, batch_id, session_id)
        .unwrap();
    let authorization_id = binding.authorization_id.clone();
    let plan_digest = binding.plan_digest.clone();
    store
        .register_authorization(RegisterAuthorization { binding })
        .unwrap();
    let claimed = store
        .claim_execution(&authorization_id, &plan_digest)
        .unwrap();
    let authorization = unclaimed.claim(claimed.fence_epoch()).unwrap();
    let actions = canonical_actions(&plan);

    Fixture {
        _temp: temp,
        store,
        claimed,
        plan,
        authorization,
        actions,
        suffix: suffix.to_string(),
    }
}

fn fixed_executor() -> SimulatedExecutor {
    SimulatedExecutor::with_test_components(
        DeterministicFakeAdapter::new(),
        FixedClock::new(base_time() + Duration::from_secs(1)),
    )
}

#[test]
fn successful_trash_and_permanent_runs_record_all_outcomes_and_consume() {
    for (mode, suffix) in [
        (DeletionMode::Trash, "success-trash"),
        (DeletionMode::Permanent, "success-permanent"),
    ] {
        let fixture = fixture(mode, 2, suffix);
        let authorization_id = fixture.claimed.authorization_id().clone();
        let plan_digest = fixture.claimed.plan_digest().clone();
        let mut executor = fixed_executor();

        let report = executor
            .execute(
                &fixture.store,
                &fixture.claimed,
                &fixture.plan,
                fixture.authorization,
                fixture.actions,
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(report.completed.len(), 2);
        assert!(matches!(report.state, ExecutionState::Completed));
        assert!(report.completed.iter().all(|receipt| receipt.mode == mode));
        fixture.store.verify_integrity().unwrap();
        drop(fixture.claimed);
        assert!(matches!(
            fixture
                .store
                .claim_recovery(&authorization_id, &plan_digest)
                .unwrap_err(),
            AuditError::AuthorizationAlreadyConsumed(_)
        ));
    }
}

#[derive(Debug, Clone)]
enum TestBehavior {
    Success,
    FailAfterSubmit,
    FailOnCall(usize),
    BadReceipt(&'static str),
    CancelAfterSubmit(CancellationToken),
}

#[derive(Debug, Clone)]
struct TestAdapter {
    calls: Arc<AtomicUsize>,
    behavior: TestBehavior,
}

impl TestAdapter {
    fn new(behavior: TestBehavior) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                calls: Arc::clone(&calls),
                behavior,
            },
            calls,
        )
    }

    fn submit<P: PermitView>(
        &mut self,
        permit: P,
        mode: DeletionMode,
    ) -> Result<Submission<P>, AdapterFailure> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if matches!(self.behavior, TestBehavior::FailAfterSubmit)
            || matches!(self.behavior, TestBehavior::FailOnCall(expected) if call == expected)
        {
            return Err(AdapterFailure);
        }
        let mut receipt = FakeReceipt::for_permit(&permit, mode);
        if let TestBehavior::BadReceipt(field) = self.behavior {
            match field {
                "action_id" => receipt.action_id = "action-wrong".to_string(),
                "attempt_id" => receipt.attempt_id = "attempt-wrong".to_string(),
                "mode" => {
                    receipt.mode = match receipt.mode {
                        DeletionMode::Trash => DeletionMode::Permanent,
                        DeletionMode::Permanent => DeletionMode::Trash,
                    };
                }
                _ => panic!("unsupported test receipt field"),
            }
        }
        if let TestBehavior::CancelAfterSubmit(token) = &self.behavior {
            token.cancel();
        }
        Ok(Submission { permit, receipt })
    }
}

impl sealed::Sealed for TestAdapter {}

impl SimulatedAdapter for TestAdapter {
    fn submit_trash(
        &mut self,
        permit: ConsumedTrashPreflightPermit,
    ) -> Result<Submission<ConsumedTrashPreflightPermit>, AdapterFailure> {
        self.submit(permit, DeletionMode::Trash)
    }

    fn submit_permanent(
        &mut self,
        permit: ConsumedPermanentPreflightPermit,
    ) -> Result<Submission<ConsumedPermanentPreflightPermit>, AdapterFailure> {
        self.submit(permit, DeletionMode::Permanent)
    }
}

fn executor_with_behavior(behavior: TestBehavior) -> (SimulatedExecutor, Arc<AtomicUsize>) {
    let (adapter, calls) = TestAdapter::new(behavior);
    (
        SimulatedExecutor::with_test_components(
            adapter,
            FixedClock::new(base_time() + Duration::from_secs(1)),
        ),
        calls,
    )
}

fn assert_rejected_before_intent(
    fixture: Fixture,
    actions: Vec<ActionRequest>,
    expected: impl FnOnce(&ValidationError) -> bool,
) {
    let before = fixture.store.verify_integrity().unwrap().latest_sequence;
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);
    let error = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            actions,
            &CancellationToken::new(),
        )
        .unwrap_err();
    let ExecutorError::Validation(validation) = error else {
        panic!("expected validation failure, got {error:?}");
    };
    assert!(
        expected(&validation),
        "unexpected validation: {validation:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.verify_integrity().unwrap().latest_sequence,
        before
    );
}

#[test]
fn duplicate_subset_unknown_and_out_of_order_requests_fail_before_intent() {
    let duplicate = fixture(DeletionMode::Trash, 2, "duplicate");
    let mut duplicate_actions = duplicate.actions.clone();
    duplicate_actions[1] = duplicate_actions[0].clone();
    assert_rejected_before_intent(duplicate, duplicate_actions, |error| {
        matches!(error, ValidationError::DuplicateActionId { .. })
    });

    let subset = fixture(DeletionMode::Trash, 2, "subset");
    let subset_actions = vec![subset.actions[0].clone()];
    assert_rejected_before_intent(subset, subset_actions, |error| {
        matches!(error, ValidationError::ActionSetMismatch)
    });

    let unknown = fixture(DeletionMode::Trash, 2, "unknown");
    let mut unknown_actions = unknown.actions.clone();
    unknown_actions[1].action_id = "action-9999".to_string();
    assert_rejected_before_intent(unknown, unknown_actions, |error| {
        matches!(error, ValidationError::UnknownAction { .. })
    });

    let reversed = fixture(DeletionMode::Trash, 2, "order");
    let mut reversed_actions = reversed.actions.clone();
    reversed_actions.reverse();
    assert_rejected_before_intent(reversed, reversed_actions, |error| {
        matches!(error, ValidationError::NonCanonicalOrder { .. })
    });
}

#[test]
fn durable_reservation_survives_restart_and_prevents_a_second_adapter_call() {
    let fixture = fixture(DeletionMode::Trash, 1, "restart");
    let audit_root = fixture._temp.path().join("audit");
    let action = &fixture.actions[0];
    let (source_path_hash, revalidation_digest) = derived_action(&fixture.plan, 0);
    let original_attempt_id = fixture
        .store
        .reserve_intent(
            &fixture.claimed,
            IntentRequest {
                item_id: ItemId::new(action.item_id.clone()).unwrap(),
                action_id: ActionId::new(action.action_id.clone()).unwrap(),
                source_path_hash: PathHash::new(source_path_hash).unwrap(),
                before_revalidation_digest: DigestString::new(revalidation_digest).unwrap(),
            },
        )
        .unwrap()
        .attempt_id()
        .as_str()
        .to_string();
    let authorization_id = fixture.claimed.authorization_id().clone();
    let plan_digest = fixture.claimed.plan_digest().clone();
    drop(fixture.claimed);
    drop(fixture.store);

    let store = AuditStore::open(audit_root).unwrap();
    let claimed = store
        .claim_recovery(&authorization_id, &plan_digest)
        .unwrap();
    let clock = FixedClock::new(base_time() + Duration::from_secs(1));
    let authorization =
        unclaimed_authorization(&fixture.plan, DeletionMode::Trash, &fixture.suffix, &clock)
            .claim(claimed.fence_epoch())
            .unwrap();
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);

    let error = executor
        .execute(
            &store,
            &claimed,
            &fixture.plan,
            authorization,
            fixture.actions,
            &CancellationToken::new(),
        )
        .unwrap_err();

    let ExecutorError::NeedsReconciliation {
        ref reconciliation,
        ref completed,
        ref authorization,
    } = error
    else {
        panic!("expected reconciliation-required result");
    };
    assert_eq!(
        reconciliation.reason,
        ReconciliationReason::ExistingDurableIntent
    );
    assert_eq!(reconciliation.attempt_id, original_attempt_id);
    assert_eq!(reconciliation.item_id, "item-0001");
    assert_eq!(reconciliation.action_id, "action-0001");
    assert!(completed.is_empty());
    assert!(matches!(
        authorization.state(),
        AuthorizationState::Claimed { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn conflicting_restart_evidence_is_recovery_required_without_adapter_call() {
    let fixture = fixture(DeletionMode::Trash, 1, "restart-conflict");
    let action = &fixture.actions[0];
    let original_attempt_id = fixture
        .store
        .reserve_intent(
            &fixture.claimed,
            IntentRequest {
                item_id: ItemId::new(action.item_id.clone()).unwrap(),
                action_id: ActionId::new(action.action_id.clone()).unwrap(),
                source_path_hash: PathHash::new("different-path-hash").unwrap(),
                before_revalidation_digest: DigestString::new("different-revalidation").unwrap(),
            },
        )
        .unwrap()
        .attempt_id()
        .as_str()
        .to_string();
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);

    let error = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions,
            &CancellationToken::new(),
        )
        .unwrap_err();

    let ExecutorError::NeedsReconciliation {
        ref reconciliation,
        ref completed,
        ref authorization,
    } = error
    else {
        panic!("expected reconciliation-required result");
    };
    assert_eq!(
        reconciliation.reason,
        ReconciliationReason::ExistingIntentConflict
    );
    assert_eq!(reconciliation.attempt_id, original_attempt_id);
    assert_eq!(reconciliation.item_id, "item-0001");
    assert_eq!(reconciliation.action_id, "action-0001");
    assert!(completed.is_empty());
    assert!(matches!(
        authorization.state(),
        AuthorizationState::Claimed { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn pre_submit_audit_failure_never_calls_the_adapter() {
    let fixture = fixture(DeletionMode::Trash, 1, "audit-failure");
    let other_temp = TempDir::new().unwrap();
    let wrong_store = AuditStore::open(other_temp.path().join("audit")).unwrap();
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);

    let error = executor
        .execute(
            &wrong_store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions,
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ExecutorError::IntentStateUncertain {
            source,
            ..
        } if matches!(*source, AuditError::AuthorizationBindingMismatch)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.store.verify_integrity().unwrap().latest_sequence, 2);
}

#[test]
fn later_conflicting_intent_stops_after_prior_durable_outcome() {
    let fixture = fixture(DeletionMode::Trash, 2, "partial-audit");
    let conflicting = &fixture.actions[1];
    fixture
        .store
        .reserve_intent(
            &fixture.claimed,
            IntentRequest {
                item_id: ItemId::new(conflicting.item_id.clone()).unwrap(),
                action_id: ActionId::new(conflicting.action_id.clone()).unwrap(),
                source_path_hash: PathHash::new("different-path-hash").unwrap(),
                before_revalidation_digest: DigestString::new("different-revalidation").unwrap(),
            },
        )
        .unwrap();
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);

    let error = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions,
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert!(matches!(
        &error,
        ExecutorError::NeedsReconciliation {
            reconciliation,
            completed,
            ..
        } if reconciliation.reason == ReconciliationReason::ExistingIntentConflict
            && completed.len() == 1
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.store.verify_integrity().unwrap().action_sequence, 3);
}

#[test]
fn ambiguous_submit_leaves_the_durable_intent_for_recovery() {
    let fixture = fixture(DeletionMode::Trash, 1, "post-submit");
    let (mut executor, calls) = executor_with_behavior(TestBehavior::FailAfterSubmit);

    let error = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions,
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert!(matches!(
        &error,
        ExecutorError::NeedsReconciliation {
            reconciliation,
            completed,
            ..
        } if reconciliation.reason == ReconciliationReason::AdapterSubmitFailed
            && completed.is_empty()
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture.store.consume_execution(&fixture.claimed),
        Err(AuditError::UnresolvedIntentsRemain)
    ));
}

#[test]
fn second_action_reconciliation_preserves_progress_and_authorization() {
    let fixture = fixture(DeletionMode::Trash, 2, "partial-reconciliation");
    let (mut executor, calls) = executor_with_behavior(TestBehavior::FailOnCall(2));

    let error = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions,
            &CancellationToken::new(),
        )
        .unwrap_err();

    let ExecutorError::NeedsReconciliation {
        reconciliation,
        completed,
        authorization,
    } = error
    else {
        panic!("expected reconciliation-required result");
    };
    assert_eq!(
        reconciliation.reason,
        ReconciliationReason::AdapterSubmitFailed
    );
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].action_id, "action-0002");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        authorization.state(),
        AuthorizationState::Claimed { .. }
    ));
    assert!(matches!(
        fixture.store.consume_execution(&fixture.claimed),
        Err(AuditError::UnresolvedIntentsRemain)
    ));
}

#[test]
fn same_simulated_target_conflicts_across_authorizations_without_submit() {
    let first_plan = plan(DeletionMode::Trash, 1, "overlap-first");
    let second_plan = plan(DeletionMode::Trash, 1, "overlap-second");
    let first_action = first_plan.ordered_simulated_actions().unwrap().remove(0);
    let second_action = second_plan.ordered_simulated_actions().unwrap().remove(0);
    assert_eq!(
        first_action.source_identity_digest(),
        second_action.source_identity_digest()
    );
    assert_ne!(
        first_action.revalidation_digest(),
        second_action.revalidation_digest()
    );

    let clock = FixedClock::new(base_time() + Duration::from_secs(1));
    let first_authorization =
        unclaimed_authorization(&first_plan, DeletionMode::Trash, "overlap-first", &clock);
    let second_authorization =
        unclaimed_authorization(&second_plan, DeletionMode::Trash, "overlap-second", &clock);
    let temp = TempDir::new().unwrap();
    let store = AuditStore::open(temp.path().join("audit")).unwrap();
    let first_binding = first_authorization
        .audit_binding(
            &first_plan,
            BatchId::new("batch-overlap-first").unwrap(),
            SessionId::new("session-overlap-first-executor").unwrap(),
        )
        .unwrap();
    let first_authorization_id = first_binding.authorization_id.clone();
    let first_plan_digest = first_binding.plan_digest.clone();
    let second_binding = second_authorization
        .audit_binding(
            &second_plan,
            BatchId::new("batch-overlap-second").unwrap(),
            SessionId::new("session-overlap-second-executor").unwrap(),
        )
        .unwrap();
    let second_authorization_id = second_binding.authorization_id.clone();
    let second_plan_digest = second_binding.plan_digest.clone();
    store
        .register_authorization(RegisterAuthorization {
            binding: first_binding,
        })
        .unwrap();
    store
        .register_authorization(RegisterAuthorization {
            binding: second_binding,
        })
        .unwrap();

    let first_claim = store
        .claim_execution(&first_authorization_id, &first_plan_digest)
        .unwrap();
    let original_attempt_id = store
        .reserve_intent(
            &first_claim,
            IntentRequest {
                item_id: ItemId::new(first_action.item_id()).unwrap(),
                action_id: ActionId::new(first_action.action_id()).unwrap(),
                source_path_hash: PathHash::new(first_action.source_identity_digest()).unwrap(),
                before_revalidation_digest: DigestString::new(first_action.revalidation_digest())
                    .unwrap(),
            },
        )
        .unwrap()
        .attempt_id()
        .as_str()
        .to_string();
    drop(first_claim);

    let second_claim = store
        .claim_execution(&second_authorization_id, &second_plan_digest)
        .unwrap();
    let second_authorization = second_authorization
        .claim(second_claim.fence_epoch())
        .unwrap();
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);
    let error = executor
        .execute(
            &store,
            &second_claim,
            &second_plan,
            second_authorization,
            canonical_actions(&second_plan),
            &CancellationToken::new(),
        )
        .unwrap_err();

    let ExecutorError::NeedsReconciliation {
        reconciliation,
        completed,
        authorization,
    } = error
    else {
        panic!("expected cross-authorization reconciliation");
    };
    assert_eq!(
        reconciliation.reason,
        ReconciliationReason::ExistingIntentConflict
    );
    assert_eq!(reconciliation.attempt_id, original_attempt_id);
    assert!(completed.is_empty());
    assert!(matches!(
        authorization.state(),
        AuthorizationState::Claimed { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn claimed_mode_mismatch_is_rejected_before_intent() {
    let plan = plan(DeletionMode::Permanent, 1, "mode-mismatch");
    let clock = FixedClock::new(base_time() + Duration::from_secs(1));
    let unclaimed =
        unclaimed_authorization(&plan, DeletionMode::Permanent, "mode-mismatch", &clock);
    let temp = TempDir::new().unwrap();
    let store = AuditStore::open(temp.path().join("audit")).unwrap();
    let mut binding = unclaimed
        .audit_binding(
            &plan,
            BatchId::new("batch-mode-mismatch").unwrap(),
            SessionId::new("session-mode-mismatch-executor").unwrap(),
        )
        .unwrap();
    binding.requested_mode = RequestedMode::Trash;
    let authorization_id = binding.authorization_id.clone();
    let plan_digest = binding.plan_digest.clone();
    store
        .register_authorization(RegisterAuthorization { binding })
        .unwrap();
    let claimed = store
        .claim_execution(&authorization_id, &plan_digest)
        .unwrap();
    let authorization = unclaimed.claim(claimed.fence_epoch()).unwrap();
    let before = store.verify_integrity().unwrap().latest_sequence;
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);

    let error = executor
        .execute(
            &store,
            &claimed,
            &plan,
            authorization,
            canonical_actions(&plan),
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ExecutorError::Validation(ValidationError::AuditBindingMismatch(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.verify_integrity().unwrap().latest_sequence, before);
}

#[test]
fn complete_audit_binding_mismatches_fail_before_intent() {
    for field in [
        "plan_id",
        "risk_by_action",
        "policy_version",
        "host_instance_id",
        "workflow_session",
    ] {
        let suffix = format!("claim-{}", field.replace('_', "-"));
        let plan = plan(DeletionMode::Trash, 1, &suffix);
        let clock = FixedClock::new(base_time() + Duration::from_secs(1));
        let unclaimed = unclaimed_authorization(&plan, DeletionMode::Trash, &suffix, &clock);
        let temp = TempDir::new().unwrap();
        let store = AuditStore::open(temp.path().join("audit")).unwrap();
        let mut binding = unclaimed
            .audit_binding(
                &plan,
                BatchId::new(format!("batch-{suffix}")).unwrap(),
                SessionId::new(format!("session-{suffix}-executor")).unwrap(),
            )
            .unwrap();
        match field {
            "plan_id" => {
                binding.plan_id = AuditPlanId::new("plan-forged-executor").unwrap();
            }
            "risk_by_action" => {
                let action_id = binding.action_ids.iter().next().unwrap().clone();
                binding.risk_by_action.insert(action_id, AuditRiskTier::R4);
            }
            "policy_version" => {
                binding.policy_version = "policy-forged".to_string();
            }
            "host_instance_id" => {
                binding.host_instance_id =
                    sweepx_audit::HostId::new("host-forged-executor").unwrap();
            }
            "workflow_session" => {
                binding.workflow_session = SessionId::new("session-forged-executor").unwrap();
            }
            _ => unreachable!(),
        }
        let authorization_id = binding.authorization_id.clone();
        let plan_digest = binding.plan_digest.clone();
        store
            .register_authorization(RegisterAuthorization { binding })
            .unwrap();
        let claimed = store
            .claim_execution(&authorization_id, &plan_digest)
            .unwrap();
        let authorization = unclaimed.claim(claimed.fence_epoch()).unwrap();
        let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);

        let error = executor
            .execute(
                &store,
                &claimed,
                &plan,
                authorization,
                canonical_actions(&plan),
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ExecutorError::Validation(ValidationError::AuditBindingMismatch(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.verify_integrity().unwrap().action_sequence, 0);
    }
}

#[test]
fn forged_action_mode_and_attempt_receipts_require_reconciliation() {
    for field in ["action_id", "mode", "attempt_id"] {
        let suffix = format!("bad-{}", field.replace('_', "-"));
        let fixture = fixture(DeletionMode::Trash, 1, &suffix);
        let (mut executor, calls) = executor_with_behavior(TestBehavior::BadReceipt(field));

        let error = executor
            .execute(
                &fixture.store,
                &fixture.claimed,
                &fixture.plan,
                fixture.authorization,
                fixture.actions,
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert!(matches!(
            &error,
            ExecutorError::NeedsReconciliation {
                reconciliation,
                completed,
                ..
            } if matches!(
                reconciliation.reason,
                ReconciliationReason::ReceiptMismatch { field: actual } if actual == field
            ) && completed.is_empty()
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            fixture.store.consume_execution(&fixture.claimed),
            Err(AuditError::UnresolvedIntentsRemain)
        ));
    }
}

#[test]
fn cancellation_stops_before_reserving_the_next_action_and_keeps_claimed_state() {
    let fixture = fixture(DeletionMode::Trash, 2, "cancel-next");
    let cancellation = CancellationToken::new();
    let (adapter, calls) = TestAdapter::new(TestBehavior::CancelAfterSubmit(cancellation.clone()));
    let mut executor = SimulatedExecutor::with_test_components(
        adapter,
        FixedClock::new(base_time() + Duration::from_secs(1)),
    );

    let report = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions.clone(),
            &cancellation,
        )
        .unwrap();

    assert_eq!(report.completed.len(), 1);
    let ExecutionState::Cancelled { authorization } = report.state else {
        panic!("expected cancellation state");
    };
    assert!(matches!(
        authorization.state(),
        AuthorizationState::Claimed { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let next = &fixture.actions[1];
    let (source_path_hash, revalidation_digest) = derived_action(&fixture.plan, 1);
    let token = fixture
        .store
        .reserve_intent(
            &fixture.claimed,
            IntentRequest {
                item_id: ItemId::new(next.item_id.clone()).unwrap(),
                action_id: ActionId::new(next.action_id.clone()).unwrap(),
                source_path_hash: PathHash::new(source_path_hash).unwrap(),
                before_revalidation_digest: DigestString::new(revalidation_digest).unwrap(),
            },
        )
        .unwrap();
    assert_eq!(token.action_id().as_str(), next.action_id);
    assert!(matches!(
        fixture.store.consume_execution(&fixture.claimed),
        Err(AuditError::UnresolvedIntentsRemain)
    ));
}

#[derive(Debug)]
struct JumpAtSubmitClock {
    calls: AtomicUsize,
}

impl JumpAtSubmitClock {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl Clock for JumpAtSubmitClock {
    fn now(&self) -> SystemTime {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < 4 {
            base_time() + Duration::from_secs(1)
        } else {
            base_time() + Duration::from_secs(1) + PERMIT_TTL
        }
    }
}

#[test]
fn permit_ttl_is_rechecked_immediately_before_submit() {
    let fixture = fixture(DeletionMode::Trash, 1, "permit-ttl");
    let (adapter, calls) = TestAdapter::new(TestBehavior::Success);
    let mut executor = SimulatedExecutor::with_test_components(adapter, JumpAtSubmitClock::new());

    let error = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions,
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert!(matches!(
        &error,
        ExecutorError::NeedsReconciliation {
            reconciliation,
            completed,
            ..
        } if reconciliation.reason == ReconciliationReason::SafetyVerificationFailed
            && completed.is_empty()
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        fixture.store.consume_execution(&fixture.claimed),
        Err(AuditError::UnresolvedIntentsRemain)
    ));
}

#[test]
fn cancellation_before_first_action_creates_no_intent() {
    let fixture = fixture(DeletionMode::Trash, 1, "cancel-first");
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let before = fixture.store.verify_integrity().unwrap().latest_sequence;
    let (mut executor, calls) = executor_with_behavior(TestBehavior::Success);

    let report = executor
        .execute(
            &fixture.store,
            &fixture.claimed,
            &fixture.plan,
            fixture.authorization,
            fixture.actions,
            &cancellation,
        )
        .unwrap();

    assert!(report.completed.is_empty());
    let ExecutionState::Cancelled { authorization } = report.state else {
        panic!("expected cancellation state");
    };
    assert!(matches!(
        authorization.state(),
        AuthorizationState::Claimed { .. }
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.verify_integrity().unwrap().latest_sequence,
        before
    );
    drop(fixture.claimed);
    assert!(
        fixture
            .store
            .claim_recovery(
                &AuthorizationId::new("simulation-cancel-first-executor").unwrap(),
                &DigestString::new(fixture.plan.canonical_digest_verified().unwrap().as_str())
                    .unwrap(),
            )
            .is_ok()
    );
}
