//! P3's serial, simulation-only execution coordinator.
//!
//! The executor accepts no native paths and exposes no adapter extension point. Durable replay
//! authority remains in [`sweepx_audit::AuditStore`]; the in-memory safety authorization and
//! permit are only one-shot capabilities for the current process.

use std::collections::BTreeSet;
use std::time::SystemTime;

use sweepx_audit::{
    ActionId, AuditError, AuditStore, ClaimedExecution, DigestString, DurableIntentToken,
    IntentRequest, ItemId, Observation, PathHash, RecoveryState, RequestedMode, SimulatedOutcome,
    StableStatus,
};
use sweepx_platform::CancellationToken;
use sweepx_safety::simulation::{
    DeterministicRevalidationObserver, issue_simulated_preflight_permit,
    verify_simulated_revalidation,
};
use sweepx_safety::{
    AuditBindingError, AuthorizationConsumeError, AuthorizationMatchError, AuthorizationState,
    CanonicalPlanError, Clock, ConsumedPermanentPreflightPermit, ConsumedPreflightPermit,
    ConsumedTrashPreflightPermit, DeletionMode, DeletionPlan, ExecutionAuthorization, PERMIT_TTL,
    RiskTier, SystemClock, consume_preflight_permit,
};
use thiserror::Error;

/// Maximum number of actions accepted in one simulated execution.
pub const MAX_ACTIONS: usize = 1024;
const MAX_BOUND_CLAIM_BYTES: usize = 256;
const MAX_SUBMISSION_ID_BYTES: usize = 256;
const ADAPTER_VERSION: &str = "sweepx-simulated-adapter-v1";
const TRASH_OPERATION: &str = "simulated_trash";
const PERMANENT_OPERATION: &str = "simulated_permanent_delete";
const SIMULATION_NOTE: &str = "simulation only; no native mutation";

/// One action in the caller-supplied canonical execution sequence.
///
/// The request carries identifiers only. Safety derives the source and revalidation digests from
/// the sealed plan. In particular, callers cannot provide a native path, identity digest, mode
/// override, attempt ID, permit, or adapter selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRequest {
    pub item_id: String,
    pub action_id: String,
}

impl ActionRequest {
    pub fn new(item_id: impl Into<String>, action_id: impl Into<String>) -> Self {
        Self {
            item_id: item_id.into(),
            action_id: action_id.into(),
        }
    }
}

/// A validated receipt for one deterministic simulated submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedActionReceipt {
    pub submission_id: String,
    pub attempt_id: String,
    pub item_id: String,
    pub action_id: String,
    pub mode: DeletionMode,
}

/// Terminal result of one executor invocation.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionReport {
    pub completed: Vec<SimulatedActionReceipt>,
    pub state: ExecutionState,
}

/// Whether the exact action sequence finished or stopped before the next action.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecutionState {
    Completed,
    Cancelled {
        /// The still-claimed local capability. No durable consume occurs on cancellation.
        authorization: Box<ExecutionAuthorization>,
    },
}

/// Fixed, bounded explanations for an unresolved post-submit intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationReason {
    /// P3 deliberately has no restart/resume path: an existing intent is never resubmitted,
    /// even if it may already have an outcome. Recovery must inspect the durable audit record.
    ExistingDurableIntent,
    IntentStateUncertain,
    ExistingIntentConflict,
    SafetyVerificationFailed,
    PermitBindingMismatch {
        field: &'static str,
    },
    AdapterSubmitFailed,
    ReceiptMismatch {
        field: &'static str,
    },
    ClockMovedBackwards,
    OutcomeAuditFailed,
}

impl std::fmt::Display for ReconciliationReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExistingDurableIntent => {
                formatter.write_str("action already has a durable intent")
            }
            Self::IntentStateUncertain => {
                formatter.write_str("durable intent state could not be verified")
            }
            Self::ExistingIntentConflict => {
                formatter.write_str("action has a conflicting durable intent")
            }
            Self::SafetyVerificationFailed => {
                formatter.write_str("simulation safety verification failed after intent")
            }
            Self::PermitBindingMismatch { field } => {
                write!(formatter, "consumed permit mismatch in {field}")
            }
            Self::AdapterSubmitFailed => formatter.write_str("simulated adapter submit failed"),
            Self::ReceiptMismatch { field } => {
                write!(formatter, "simulated receipt mismatch in {field}")
            }
            Self::ClockMovedBackwards => formatter.write_str("clock moved backwards after submit"),
            Self::OutcomeAuditFailed => formatter.write_str("durable outcome write failed"),
        }
    }
}

/// The durable intent that must be reconciled before any retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationRequired {
    pub attempt_id: String,
    pub item_id: String,
    pub action_id: String,
    pub reason: ReconciliationReason,
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("execution request validation failed: {0}")]
    Validation(#[from] ValidationError),
    #[error("audit operation failed before execution: {0}")]
    Audit(#[from] AuditError),
    #[error("local authorization finalization failed: {source}")]
    AuthorizationConsume {
        completed: Vec<SimulatedActionReceipt>,
        #[source]
        source: AuthorizationConsumeError,
    },
    #[error("durable execution finalization failed after every action outcome: {source}")]
    Finalization {
        completed: Vec<SimulatedActionReceipt>,
        authorization: Box<ExecutionAuthorization>,
        #[source]
        source: AuditError,
    },
    #[error(
        "execution stopped after durable outcomes because the next audit operation failed: {source}"
    )]
    PartialAudit {
        completed: Vec<SimulatedActionReceipt>,
        authorization: Box<ExecutionAuthorization>,
        #[source]
        source: AuditError,
    },
    #[error("durable intent state is uncertain for action {action_id}: {source}")]
    IntentStateUncertain {
        item_id: String,
        action_id: String,
        reason: ReconciliationReason,
        completed: Vec<SimulatedActionReceipt>,
        authorization: Box<ExecutionAuthorization>,
        #[source]
        source: Box<AuditError>,
    },
    #[error("durable intent requires reconciliation: {reconciliation:?}")]
    NeedsReconciliation {
        reconciliation: Box<ReconciliationRequired>,
        completed: Vec<SimulatedActionReceipt>,
        authorization: Box<ExecutionAuthorization>,
    },
}

impl ExecutorError {
    /// Outcomes already made durable before this invocation stopped.
    pub fn completed(&self) -> &[SimulatedActionReceipt] {
        match self {
            Self::AuthorizationConsume { completed, .. }
            | Self::Finalization { completed, .. }
            | Self::PartialAudit { completed, .. }
            | Self::IntentStateUncertain { completed, .. }
            | Self::NeedsReconciliation { completed, .. } => completed,
            _ => &[],
        }
    }

    /// Recovers the still-claimed local authorization from a non-terminal audit failure.
    pub fn into_authorization(self) -> Option<ExecutionAuthorization> {
        match self {
            Self::Finalization { authorization, .. }
            | Self::PartialAudit { authorization, .. }
            | Self::IntentStateUncertain { authorization, .. }
            | Self::NeedsReconciliation { authorization, .. } => Some(*authorization),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("action count must be between 1 and {MAX_ACTIONS}")]
    InvalidActionCount,
    #[error("plan contains duplicate item identifiers")]
    DuplicatePlanItemId,
    #[error("plan contains duplicate action identifiers")]
    DuplicatePlanActionId,
    #[error("failed to derive sealed simulated action bindings: {0}")]
    ActionBinding(#[source] CanonicalPlanError),
    #[error("action {index} has an invalid {field}")]
    InvalidActionField { index: usize, field: &'static str },
    #[error("action request contains duplicate action id {action_id}")]
    DuplicateActionId { action_id: String },
    #[error("action {item_id}:{action_id} is not in the exact plan")]
    UnknownAction { item_id: String, action_id: String },
    #[error("requested actions are not the exact plan action set")]
    ActionSetMismatch,
    #[error("action {index} is not in canonical plan order")]
    NonCanonicalOrder { index: usize },
    #[error("authorization does not match the exact plan: {0}")]
    AuthorizationMismatch(#[source] AuthorizationMatchError),
    #[error("durable audit claim does not exactly match the sealed plan authorization: {0}")]
    AuditBindingMismatch(#[source] AuditBindingError),
    #[error("claimed execution binding differs in {field}")]
    ClaimedExecutionMismatch { field: &'static str },
}

mod sealed {
    pub trait Sealed {}
}

/// The only P3 adapter available to callers. It never performs native mutation.
#[derive(Debug, Default)]
pub struct DeterministicFakeAdapter {
    _sealed: (),
}

impl DeterministicFakeAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl sealed::Sealed for DeterministicFakeAdapter {}

trait SimulatedAdapter: sealed::Sealed + Send {
    fn submit_trash(
        &mut self,
        permit: ConsumedTrashPreflightPermit,
    ) -> Result<Submission<ConsumedTrashPreflightPermit>, AdapterFailure>;

    fn submit_permanent(
        &mut self,
        permit: ConsumedPermanentPreflightPermit,
    ) -> Result<Submission<ConsumedPermanentPreflightPermit>, AdapterFailure>;
}

impl SimulatedAdapter for DeterministicFakeAdapter {
    fn submit_trash(
        &mut self,
        permit: ConsumedTrashPreflightPermit,
    ) -> Result<Submission<ConsumedTrashPreflightPermit>, AdapterFailure> {
        Ok(Submission {
            receipt: FakeReceipt::for_permit(&permit, DeletionMode::Trash),
            permit,
        })
    }

    fn submit_permanent(
        &mut self,
        permit: ConsumedPermanentPreflightPermit,
    ) -> Result<Submission<ConsumedPermanentPreflightPermit>, AdapterFailure> {
        Ok(Submission {
            receipt: FakeReceipt::for_permit(&permit, DeletionMode::Permanent),
            permit,
        })
    }
}

#[derive(Debug)]
struct AdapterFailure;

struct Submission<P> {
    permit: P,
    receipt: FakeReceipt,
}

#[derive(Debug, Clone)]
struct FakeReceipt {
    submission_id: String,
    authorization_id: String,
    batch_id: String,
    plan_id: String,
    plan_digest: String,
    item_id: String,
    action_id: String,
    attempt_id: String,
    nonce: String,
    mode: DeletionMode,
    risk_tier: RiskTier,
    fence_epoch: u64,
    source_path_hash: String,
    revalidation_digest: String,
    policy_version: String,
    policy_digest: String,
    protected_anchor_snapshot_digest: String,
    final_parent_identity: String,
    final_object_identity: String,
    final_filesystem_object_domain_identity: String,
    final_volume_or_mount_identity: String,
    adapter_version: String,
    actual_platform_operation: String,
    stable_status: StableStatus,
    recovery_state: RecoveryState,
    source_postcheck: Observation,
    destination_postcheck: Option<Observation>,
    resulting_trash_locator: Option<String>,
}

impl FakeReceipt {
    fn for_permit(permit: &impl PermitView, mode: DeletionMode) -> Self {
        let intent = permit.durable_intent();
        let attempt_id = intent.attempt_id().as_str();
        let (operation, stable_status, recovery_state, destination, locator) = match mode {
            DeletionMode::Trash => (
                TRASH_OPERATION,
                StableStatus::TrashSucceededLocationReported,
                RecoveryState::TrashLocationReported,
                Some(Observation {
                    exists: true,
                    identity: Some(format!("simulation:trash-destination:{attempt_id}")),
                }),
                Some(format!("simulation:trash:{attempt_id}")),
            ),
            DeletionMode::Permanent => (
                PERMANENT_OPERATION,
                StableStatus::PermanentDeleteSucceeded,
                RecoveryState::InapplicablePermanent,
                None,
                None,
            ),
        };
        Self {
            submission_id: format!("simulation:{attempt_id}"),
            authorization_id: permit.authorization_id().to_string(),
            batch_id: intent.batch_id().as_str().to_string(),
            plan_id: permit.plan_id().to_string(),
            plan_digest: permit.plan_digest().to_string(),
            item_id: permit.item_id().to_string(),
            action_id: permit.action_id().to_string(),
            attempt_id: attempt_id.to_string(),
            nonce: permit.one_shot_nonce().to_string(),
            mode,
            risk_tier: permit.risk_tier(),
            fence_epoch: permit.fence_epoch(),
            source_path_hash: intent.source_path_hash().as_str().to_string(),
            revalidation_digest: permit.revalidation_digest().to_string(),
            policy_version: permit.policy_version().to_string(),
            policy_digest: permit.policy_digest().to_string(),
            protected_anchor_snapshot_digest: permit.protected_anchor_snapshot_digest().to_string(),
            final_parent_identity: permit.final_parent_identity().to_string(),
            final_object_identity: permit.final_object_identity().to_string(),
            final_filesystem_object_domain_identity: permit
                .final_filesystem_object_domain_identity()
                .to_string(),
            final_volume_or_mount_identity: permit.final_volume_or_mount_identity().to_string(),
            adapter_version: ADAPTER_VERSION.to_string(),
            actual_platform_operation: operation.to_string(),
            stable_status,
            recovery_state,
            source_postcheck: Observation {
                exists: false,
                identity: None,
            },
            destination_postcheck: destination,
            resulting_trash_locator: locator,
        }
    }
}

/// Serial P3 executor. The adapter extension point and clock override are private.
pub struct SimulatedExecutor {
    adapter: Box<dyn SimulatedAdapter>,
    clock: Box<dyn Clock>,
}

impl std::fmt::Debug for SimulatedExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SimulatedExecutor")
            .finish_non_exhaustive()
    }
}

impl SimulatedExecutor {
    /// Creates an executor backed by the sole public simulation adapter and a trusted system
    /// clock.
    pub fn new(adapter: DeterministicFakeAdapter) -> Self {
        Self {
            adapter: Box::new(adapter),
            clock: Box::new(SystemClock),
        }
    }

    /// Executes exactly the plan's canonical action sequence.
    ///
    /// All request validation completes before the first intent. Once a durable intent is known
    /// to exist for the current action, every subsequent failure is conservatively returned as
    /// [`ExecutorError::NeedsReconciliation`]. An ambiguous reservation error is reported as
    /// uncertain durable state, preserving prior outcomes when this is a later action.
    ///
    /// P3 does not resume or replay an existing intent. A restart encounters
    /// [`ReconciliationReason::ExistingDurableIntent`] and fails closed without calling the
    /// adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &mut self,
        audit: &AuditStore,
        claimed: &ClaimedExecution,
        plan: &DeletionPlan,
        authorization: ExecutionAuthorization,
        actions: Vec<ActionRequest>,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionReport, ExecutorError> {
        let validated =
            validate_request(claimed, plan, &authorization, actions, self.clock.as_ref())?;

        let mut completed = Vec::with_capacity(validated.actions.len());
        for action in validated.actions {
            if cancellation.is_cancelled() {
                return Ok(ExecutionReport {
                    completed,
                    state: ExecutionState::Cancelled {
                        authorization: Box::new(authorization),
                    },
                });
            }

            let reservation = audit.reserve_intent_once(
                claimed,
                IntentRequest {
                    item_id: action.item_id.clone(),
                    action_id: action.action_id.clone(),
                    source_path_hash: action.source_path_hash.clone(),
                    before_revalidation_digest: action.revalidation_digest.clone(),
                },
            );
            let durable_intent = match reservation {
                Ok(sweepx_audit::IntentReservation::Created(token)) => token,
                Ok(sweepx_audit::IntentReservation::Existing(info)) => {
                    return Err(reconciliation_error(
                        reconciliation_for_info(&info),
                        ReconciliationReason::ExistingDurableIntent,
                        completed,
                        authorization,
                    ));
                }
                Ok(sweepx_audit::IntentReservation::Conflicting(info)) => {
                    return Err(reconciliation_error(
                        reconciliation_for_info(&info),
                        ReconciliationReason::ExistingIntentConflict,
                        completed,
                        authorization,
                    ));
                }
                Err(source) if completed.is_empty() => {
                    return Err(ExecutorError::IntentStateUncertain {
                        item_id: action.item_id.as_str().to_string(),
                        action_id: action.action_id.as_str().to_string(),
                        reason: ReconciliationReason::IntentStateUncertain,
                        completed,
                        authorization: Box::new(authorization),
                        source: Box::new(source),
                    });
                }
                Err(source) => {
                    return Err(ExecutorError::PartialAudit {
                        completed,
                        authorization: Box::new(authorization),
                        source,
                    });
                }
            };
            let reconciliation = reconciliation_for_intent(&durable_intent);
            let proof = verify_simulated_revalidation(
                &DeterministicRevalidationObserver::new(),
                &durable_intent,
            );
            if durable_intent.validate_current_process().is_err() {
                return Err(reconciliation_error(
                    reconciliation,
                    ReconciliationReason::SafetyVerificationFailed,
                    completed,
                    authorization,
                ));
            }
            let permit = issue_simulated_preflight_permit(
                plan,
                &authorization,
                durable_intent,
                proof,
                self.clock.as_ref(),
            );
            let permit = match permit {
                Ok(permit) => permit,
                Err(_) => {
                    return Err(reconciliation_error(
                        reconciliation,
                        ReconciliationReason::SafetyVerificationFailed,
                        completed,
                        authorization,
                    ));
                }
            };
            let consumed = match consume_preflight_permit(&permit, self.clock.as_ref()) {
                Ok(consumed) => consumed,
                Err(_) => {
                    return Err(reconciliation_error(
                        reconciliation,
                        ReconciliationReason::SafetyVerificationFailed,
                        completed,
                        authorization,
                    ));
                }
            };

            let result = match consumed {
                ConsumedPreflightPermit::Trash(permit) => self.execute_trash(
                    audit,
                    claimed,
                    &authorization,
                    &action,
                    permit,
                    reconciliation,
                ),
                ConsumedPreflightPermit::Permanent(permit) => self.execute_permanent(
                    audit,
                    claimed,
                    &authorization,
                    &action,
                    permit,
                    reconciliation,
                ),
            };
            let receipt = match result {
                Ok(receipt) => receipt,
                Err(reconciliation) => {
                    return Err(ExecutorError::NeedsReconciliation {
                        reconciliation: Box::new(reconciliation),
                        completed,
                        authorization: Box::new(authorization),
                    });
                }
            };
            completed.push(receipt);
        }

        if let Err(source) = audit.consume_execution(claimed) {
            return Err(ExecutorError::Finalization {
                completed,
                authorization: Box::new(authorization),
                source,
            });
        }
        match authorization.consume() {
            Ok(consumed) => drop(consumed),
            Err(source) => {
                return Err(ExecutorError::AuthorizationConsume { completed, source });
            }
        }

        Ok(ExecutionReport {
            completed,
            state: ExecutionState::Completed,
        })
    }

    fn execute_trash(
        &mut self,
        audit: &AuditStore,
        claimed: &ClaimedExecution,
        authorization: &ExecutionAuthorization,
        action: &ValidatedAction,
        permit: ConsumedTrashPreflightPermit,
        reconciliation: ReconciliationRequired,
    ) -> Result<SimulatedActionReceipt, ReconciliationRequired> {
        validate_consumed_authority(&permit, claimed, authorization, action).map_err(|field| {
            reconciliation_with_reason(
                reconciliation.clone(),
                ReconciliationReason::PermitBindingMismatch { field },
            )
        })?;
        let started_at = self.clock.now();
        permit
            .validate_for_submit(self.clock.as_ref())
            .map_err(|_| {
                reconciliation_with_reason(
                    reconciliation.clone(),
                    ReconciliationReason::SafetyVerificationFailed,
                )
            })?;
        let submission = self.adapter.submit_trash(permit).map_err(|_| {
            reconciliation_with_reason(
                reconciliation.clone(),
                ReconciliationReason::AdapterSubmitFailed,
            )
        })?;
        let finished_at = self.clock.now();
        finish_submission(
            audit,
            claimed,
            submission,
            started_at,
            finished_at,
            reconciliation,
        )
    }

    fn execute_permanent(
        &mut self,
        audit: &AuditStore,
        claimed: &ClaimedExecution,
        authorization: &ExecutionAuthorization,
        action: &ValidatedAction,
        permit: ConsumedPermanentPreflightPermit,
        reconciliation: ReconciliationRequired,
    ) -> Result<SimulatedActionReceipt, ReconciliationRequired> {
        validate_consumed_authority(&permit, claimed, authorization, action).map_err(|field| {
            reconciliation_with_reason(
                reconciliation.clone(),
                ReconciliationReason::PermitBindingMismatch { field },
            )
        })?;
        let started_at = self.clock.now();
        permit
            .validate_for_submit(self.clock.as_ref())
            .map_err(|_| {
                reconciliation_with_reason(
                    reconciliation.clone(),
                    ReconciliationReason::SafetyVerificationFailed,
                )
            })?;
        let submission = self.adapter.submit_permanent(permit).map_err(|_| {
            reconciliation_with_reason(
                reconciliation.clone(),
                ReconciliationReason::AdapterSubmitFailed,
            )
        })?;
        let finished_at = self.clock.now();
        finish_submission(
            audit,
            claimed,
            submission,
            started_at,
            finished_at,
            reconciliation,
        )
    }

    #[cfg(test)]
    fn with_test_components(
        adapter: impl SimulatedAdapter + 'static,
        clock: impl Clock + 'static,
    ) -> Self {
        Self {
            adapter: Box::new(adapter),
            clock: Box::new(clock),
        }
    }
}

impl Default for SimulatedExecutor {
    fn default() -> Self {
        Self::new(DeterministicFakeAdapter::new())
    }
}

#[derive(Debug)]
struct ValidatedExecution {
    actions: Vec<ValidatedAction>,
}

#[derive(Debug)]
struct ValidatedAction {
    item_id: ItemId,
    action_id: ActionId,
    source_path_hash: PathHash,
    revalidation_digest: DigestString,
    risk_tier: RiskTier,
}

fn validate_request(
    claimed: &ClaimedExecution,
    plan: &DeletionPlan,
    authorization: &ExecutionAuthorization,
    actions: Vec<ActionRequest>,
    clock: &dyn Clock,
) -> Result<ValidatedExecution, ValidationError> {
    authorization
        .matches_audit_binding(plan, claimed.binding())
        .map_err(ValidationError::AuditBindingMismatch)?;
    authorization
        .matches_plan(plan, clock)
        .map_err(ValidationError::AuthorizationMismatch)?;

    if claimed.authorization_id().as_str() != authorization.authorization_id() {
        return Err(ValidationError::ClaimedExecutionMismatch {
            field: "authorization_id",
        });
    }
    if claimed.plan_digest().as_str() != authorization.plan_digest().as_str() {
        return Err(ValidationError::ClaimedExecutionMismatch {
            field: "plan_digest",
        });
    }
    if claimed.plan_id().as_str() != plan.plan_id().as_str() {
        return Err(ValidationError::ClaimedExecutionMismatch { field: "plan_id" });
    }
    if claimed.requested_mode() != requested_mode(authorization.mode()) {
        return Err(ValidationError::ClaimedExecutionMismatch { field: "mode" });
    }
    if !authorization.is_deterministic_simulation()
        || claimed.authorization_source()
            != sweepx_audit::AuthorizationSource::DeterministicSimulation
    {
        return Err(ValidationError::ClaimedExecutionMismatch {
            field: "authorization_source",
        });
    }
    if authorization.state()
        != (AuthorizationState::Claimed {
            fence_epoch: claimed.fence_epoch(),
        })
    {
        return Err(ValidationError::ClaimedExecutionMismatch {
            field: "fence_epoch",
        });
    }

    let expected = canonical_plan_actions(plan)?;
    for action in &expected {
        let audit_action_id = ActionId::new(action.action_id.as_str()).map_err(|_| {
            ValidationError::InvalidActionField {
                index: 0,
                field: "plan.action_id",
            }
        })?;
        if claimed.risk_for_action(&audit_action_id) != Some(to_audit_risk(action.risk_tier)) {
            return Err(ValidationError::ClaimedExecutionMismatch {
                field: "risk_by_action",
            });
        }
    }
    if actions.is_empty() || actions.len() > MAX_ACTIONS {
        return Err(ValidationError::InvalidActionCount);
    }

    for (index, action) in actions.iter().enumerate() {
        validate_stable_field(index, "item_id", &action.item_id)?;
        validate_stable_field(index, "action_id", &action.action_id)?;
    }

    let expected_set = expected
        .iter()
        .map(|action| {
            (
                action.item_id.as_str().to_string(),
                action.action_id.as_str().to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut seen_ids = BTreeSet::new();
    let mut actual_set = BTreeSet::new();
    for action in &actions {
        if !seen_ids.insert(action.action_id.clone()) {
            return Err(ValidationError::DuplicateActionId {
                action_id: action.action_id.clone(),
            });
        }
        let pair = (action.item_id.clone(), action.action_id.clone());
        if !expected_set.contains(&pair) {
            return Err(ValidationError::UnknownAction {
                item_id: pair.0,
                action_id: pair.1,
            });
        }
        actual_set.insert(pair);
    }
    if actual_set != expected_set || actions.len() != expected.len() {
        return Err(ValidationError::ActionSetMismatch);
    }
    if let Some((index, _)) =
        actions
            .iter()
            .zip(&expected)
            .enumerate()
            .find(|(_, (actual, expected))| {
                actual.item_id != expected.item_id.as_str()
                    || actual.action_id != expected.action_id.as_str()
            })
    {
        return Err(ValidationError::NonCanonicalOrder { index });
    }

    Ok(ValidatedExecution { actions: expected })
}

fn canonical_plan_actions(plan: &DeletionPlan) -> Result<Vec<ValidatedAction>, ValidationError> {
    let selected = plan.selected_action_set();
    if plan.item_ids().len() != selected.item_count {
        return Err(ValidationError::DuplicatePlanItemId);
    }
    if selected.action_count == 0 || selected.action_count > MAX_ACTIONS {
        return Err(ValidationError::InvalidActionCount);
    }
    if selected.action_ids.len() != selected.action_count
        || selected.action_count != plan.action_count()
    {
        return Err(ValidationError::DuplicatePlanActionId);
    }

    let actions = plan
        .ordered_simulated_actions()
        .map_err(ValidationError::ActionBinding)?;
    let mut seen_action_ids = BTreeSet::new();
    let mut validated = Vec::with_capacity(actions.len());
    for (index, action) in actions.into_iter().enumerate() {
        if plan.exact_item(action.item_id()).is_none() {
            return Err(ValidationError::DuplicatePlanItemId);
        }
        if !seen_action_ids.insert(action.action_id().to_string()) {
            return Err(ValidationError::DuplicatePlanActionId);
        }
        validated.push(ValidatedAction {
            item_id: ItemId::new(action.item_id()).map_err(|_| {
                ValidationError::InvalidActionField {
                    index,
                    field: "plan.item_id",
                }
            })?,
            action_id: ActionId::new(action.action_id()).map_err(|_| {
                ValidationError::InvalidActionField {
                    index,
                    field: "plan.action_id",
                }
            })?,
            source_path_hash: PathHash::new(action.source_identity_digest()).map_err(|_| {
                ValidationError::InvalidActionField {
                    index,
                    field: "derived.source_identity_digest",
                }
            })?,
            revalidation_digest: DigestString::new(action.revalidation_digest()).map_err(|_| {
                ValidationError::InvalidActionField {
                    index,
                    field: "derived.revalidation_digest",
                }
            })?,
            risk_tier: action.risk_tier(),
        });
    }
    if seen_action_ids != selected.action_ids || validated.len() != selected.action_count {
        return Err(ValidationError::DuplicatePlanActionId);
    }
    Ok(validated)
}

fn validate_stable_field(
    index: usize,
    field: &'static str,
    value: &str,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::InvalidActionField { index, field });
    }
    Ok(())
}

trait PermitView {
    fn durable_intent(&self) -> &DurableIntentToken;
    fn authorization_id(&self) -> &str;
    fn plan_id(&self) -> &str;
    fn plan_digest(&self) -> &str;
    fn item_id(&self) -> &str;
    fn action_id(&self) -> &str;
    fn mode(&self) -> DeletionMode;
    fn risk_tier(&self) -> RiskTier;
    fn fence_epoch(&self) -> u64;
    fn validated_at(&self) -> SystemTime;
    fn expires_at(&self) -> SystemTime;
    fn policy_version(&self) -> &str;
    fn policy_digest(&self) -> &str;
    fn protected_anchor_snapshot_digest(&self) -> &str;
    fn final_parent_identity(&self) -> &str;
    fn final_object_identity(&self) -> &str;
    fn final_filesystem_object_domain_identity(&self) -> &str;
    fn final_volume_or_mount_identity(&self) -> &str;
    fn revalidation_digest(&self) -> &str;
    fn one_shot_nonce(&self) -> &str;
}

macro_rules! impl_permit_view {
    ($permit:ty) => {
        impl PermitView for $permit {
            fn durable_intent(&self) -> &DurableIntentToken {
                self.durable_intent()
            }
            fn authorization_id(&self) -> &str {
                self.authorization_id()
            }
            fn plan_id(&self) -> &str {
                self.plan_id()
            }
            fn plan_digest(&self) -> &str {
                self.plan_digest().as_str()
            }
            fn item_id(&self) -> &str {
                self.item_id()
            }
            fn action_id(&self) -> &str {
                self.action_id()
            }
            fn mode(&self) -> DeletionMode {
                self.mode()
            }
            fn risk_tier(&self) -> RiskTier {
                self.risk_tier()
            }
            fn fence_epoch(&self) -> u64 {
                self.fence_epoch()
            }
            fn validated_at(&self) -> SystemTime {
                self.validated_at()
            }
            fn expires_at(&self) -> SystemTime {
                self.expires_at()
            }
            fn policy_version(&self) -> &str {
                self.policy_version()
            }
            fn policy_digest(&self) -> &str {
                self.policy_digest()
            }
            fn protected_anchor_snapshot_digest(&self) -> &str {
                self.protected_anchor_snapshot_digest()
            }
            fn final_parent_identity(&self) -> &str {
                self.final_parent_identity()
            }
            fn final_object_identity(&self) -> &str {
                self.final_object_identity()
            }
            fn final_filesystem_object_domain_identity(&self) -> &str {
                self.final_filesystem_object_domain_identity()
            }
            fn final_volume_or_mount_identity(&self) -> &str {
                self.final_volume_or_mount_identity()
            }
            fn revalidation_digest(&self) -> &str {
                self.revalidation_digest()
            }
            fn one_shot_nonce(&self) -> &str {
                self.one_shot_nonce()
            }
        }
    };
}

impl_permit_view!(ConsumedTrashPreflightPermit);
impl_permit_view!(ConsumedPermanentPreflightPermit);

fn validate_consumed_authority(
    permit: &impl PermitView,
    claimed: &ClaimedExecution,
    authorization: &ExecutionAuthorization,
    action: &ValidatedAction,
) -> Result<(), &'static str> {
    let intent = permit.durable_intent();
    let checks = [
        (
            permit.authorization_id() == authorization.authorization_id(),
            "authorization_id",
        ),
        (
            permit.authorization_id() == claimed.authorization_id().as_str(),
            "claimed_authorization_id",
        ),
        (permit.plan_id() == claimed.plan_id().as_str(), "plan_id"),
        (
            permit.plan_digest() == claimed.plan_digest().as_str(),
            "plan_digest",
        ),
        (permit.item_id() == action.item_id.as_str(), "item_id"),
        (permit.action_id() == action.action_id.as_str(), "action_id"),
        (permit.mode() == authorization.mode(), "mode"),
        (permit.fence_epoch() == claimed.fence_epoch(), "fence_epoch"),
        (
            permit.revalidation_digest() == action.revalidation_digest.as_str(),
            "revalidation_digest",
        ),
        (
            intent.authorization_id().as_str() == permit.authorization_id(),
            "intent_authorization_id",
        ),
        (intent.batch_id() == claimed.batch_id(), "batch_id"),
        (
            intent.plan_id().as_str() == permit.plan_id(),
            "intent_plan_id",
        ),
        (
            intent.plan_digest().as_str() == permit.plan_digest(),
            "intent_plan_digest",
        ),
        (
            intent.item_id().as_str() == permit.item_id(),
            "intent_item_id",
        ),
        (
            intent.action_id().as_str() == permit.action_id(),
            "intent_action_id",
        ),
        (
            requested_mode(permit.mode()) == intent.requested_mode(),
            "intent_mode",
        ),
        (
            to_audit_risk(permit.risk_tier()) == intent.risk_tier(),
            "risk_tier",
        ),
        (
            intent.fence_epoch() == permit.fence_epoch(),
            "intent_fence_epoch",
        ),
        (
            intent.source_path_hash() == &action.source_path_hash,
            "source_path_hash",
        ),
        (
            intent.before_revalidation_digest() == &action.revalidation_digest,
            "intent_revalidation_digest",
        ),
        (intent.nonce().as_str() == permit.one_shot_nonce(), "nonce"),
    ];
    if let Some((_, field)) = checks.into_iter().find(|(matches, _)| !matches) {
        return Err(field);
    }

    validate_bound_claim("attempt_id", intent.attempt_id().as_str())?;
    validate_bound_claim("policy_version", permit.policy_version())?;
    validate_bound_claim("policy_digest", permit.policy_digest())?;
    validate_bound_claim(
        "protected_anchor_snapshot_digest",
        permit.protected_anchor_snapshot_digest(),
    )?;
    validate_bound_claim("final_parent_identity", permit.final_parent_identity())?;
    validate_bound_claim("final_object_identity", permit.final_object_identity())?;
    validate_bound_claim(
        "final_filesystem_object_domain_identity",
        permit.final_filesystem_object_domain_identity(),
    )?;
    validate_bound_claim(
        "final_volume_or_mount_identity",
        permit.final_volume_or_mount_identity(),
    )?;
    if permit
        .expires_at()
        .duration_since(permit.validated_at())
        .ok()
        != Some(PERMIT_TTL)
    {
        return Err("permit_ttl");
    }
    Ok(())
}

fn validate_bound_claim(field: &'static str, value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > MAX_BOUND_CLAIM_BYTES {
        return Err(field);
    }
    Ok(())
}

fn finish_submission<P: PermitView>(
    audit: &AuditStore,
    claimed: &ClaimedExecution,
    submission: Submission<P>,
    started_at: SystemTime,
    finished_at: SystemTime,
    reconciliation: ReconciliationRequired,
) -> Result<SimulatedActionReceipt, ReconciliationRequired> {
    if finished_at.duration_since(started_at).is_err() {
        return Err(reconciliation_with_reason(
            reconciliation,
            ReconciliationReason::ClockMovedBackwards,
        ));
    }
    if let Err(field) = validate_receipt(&submission.receipt, &submission.permit) {
        return Err(reconciliation_with_reason(
            reconciliation,
            ReconciliationReason::ReceiptMismatch { field },
        ));
    }

    let receipt = submission.receipt;
    let report_receipt = SimulatedActionReceipt {
        submission_id: receipt.submission_id.clone(),
        attempt_id: receipt.attempt_id.clone(),
        item_id: receipt.item_id.clone(),
        action_id: receipt.action_id.clone(),
        mode: receipt.mode,
    };
    let outcome = match receipt.mode {
        DeletionMode::Trash => SimulatedOutcome::trash_success(
            receipt.adapter_version,
            started_at,
            finished_at,
            receipt.source_postcheck,
            receipt
                .destination_postcheck
                .expect("validated trash receipt has destination evidence"),
            receipt.resulting_trash_locator,
            receipt.submission_id,
            vec![SIMULATION_NOTE.to_string()],
        ),
        DeletionMode::Permanent => SimulatedOutcome::permanent_success(
            receipt.adapter_version,
            started_at,
            finished_at,
            receipt.source_postcheck,
            receipt.submission_id,
            vec![SIMULATION_NOTE.to_string()],
        ),
    }
    .map_err(|_| {
        reconciliation_with_reason(
            reconciliation.clone(),
            ReconciliationReason::OutcomeAuditFailed,
        )
    })?;
    audit
        .record_outcome(claimed, submission.permit.durable_intent(), outcome)
        .map_err(|_| {
            reconciliation_with_reason(reconciliation, ReconciliationReason::OutcomeAuditFailed)
        })?;
    Ok(report_receipt)
}

fn validate_receipt(receipt: &FakeReceipt, permit: &impl PermitView) -> Result<(), &'static str> {
    let intent = permit.durable_intent();
    let expected_submission_id = format!("simulation:{}", intent.attempt_id().as_str());
    if receipt.submission_id.is_empty()
        || receipt.submission_id.len() > MAX_SUBMISSION_ID_BYTES
        || receipt.submission_id != expected_submission_id
    {
        return Err("submission_id");
    }
    let checks = [
        (
            receipt.authorization_id == permit.authorization_id(),
            "authorization_id",
        ),
        (receipt.batch_id == intent.batch_id().as_str(), "batch_id"),
        (receipt.plan_id == permit.plan_id(), "plan_id"),
        (receipt.plan_digest == permit.plan_digest(), "plan_digest"),
        (receipt.item_id == permit.item_id(), "item_id"),
        (receipt.action_id == permit.action_id(), "action_id"),
        (
            receipt.attempt_id == intent.attempt_id().as_str(),
            "attempt_id",
        ),
        (receipt.nonce == permit.one_shot_nonce(), "nonce"),
        (receipt.mode == permit.mode(), "mode"),
        (receipt.risk_tier == permit.risk_tier(), "risk_tier"),
        (receipt.fence_epoch == permit.fence_epoch(), "fence_epoch"),
        (
            receipt.source_path_hash == intent.source_path_hash().as_str(),
            "source_path_hash",
        ),
        (
            receipt.revalidation_digest == permit.revalidation_digest(),
            "revalidation_digest",
        ),
        (
            receipt.policy_version == permit.policy_version(),
            "policy_version",
        ),
        (
            receipt.policy_digest == permit.policy_digest(),
            "policy_digest",
        ),
        (
            receipt.protected_anchor_snapshot_digest == permit.protected_anchor_snapshot_digest(),
            "protected_anchor_snapshot_digest",
        ),
        (
            receipt.final_parent_identity == permit.final_parent_identity(),
            "final_parent_identity",
        ),
        (
            receipt.final_object_identity == permit.final_object_identity(),
            "final_object_identity",
        ),
        (
            receipt.final_filesystem_object_domain_identity
                == permit.final_filesystem_object_domain_identity(),
            "final_filesystem_object_domain_identity",
        ),
        (
            receipt.final_volume_or_mount_identity == permit.final_volume_or_mount_identity(),
            "final_volume_or_mount_identity",
        ),
        (
            receipt.adapter_version == ADAPTER_VERSION,
            "adapter_version",
        ),
    ];
    if let Some((_, field)) = checks.into_iter().find(|(matches, _)| !matches) {
        return Err(field);
    }
    match receipt.mode {
        DeletionMode::Trash
            if receipt.actual_platform_operation == TRASH_OPERATION
                && receipt.stable_status == StableStatus::TrashSucceededLocationReported
                && receipt.recovery_state == RecoveryState::TrashLocationReported
                && !receipt.source_postcheck.exists
                && receipt
                    .destination_postcheck
                    .as_ref()
                    .is_some_and(|observation| observation.exists)
                && receipt.resulting_trash_locator.is_some() =>
        {
            Ok(())
        }
        DeletionMode::Permanent
            if receipt.actual_platform_operation == PERMANENT_OPERATION
                && receipt.stable_status == StableStatus::PermanentDeleteSucceeded
                && receipt.recovery_state == RecoveryState::InapplicablePermanent
                && !receipt.source_postcheck.exists
                && receipt.destination_postcheck.is_none()
                && receipt.resulting_trash_locator.is_none() =>
        {
            Ok(())
        }
        _ => Err("mode_semantics"),
    }
}

fn reconciliation_for_intent(intent: &DurableIntentToken) -> ReconciliationRequired {
    ReconciliationRequired {
        attempt_id: intent.attempt_id().as_str().to_string(),
        item_id: intent.item_id().as_str().to_string(),
        action_id: intent.action_id().as_str().to_string(),
        reason: ReconciliationReason::AdapterSubmitFailed,
    }
}

fn reconciliation_for_info(info: &sweepx_audit::IntentReservationInfo) -> ReconciliationRequired {
    ReconciliationRequired {
        attempt_id: info.attempt_id().as_str().to_string(),
        item_id: info.item_id().as_str().to_string(),
        action_id: info.action_id().as_str().to_string(),
        reason: ReconciliationReason::ExistingDurableIntent,
    }
}

fn to_audit_risk(risk: RiskTier) -> sweepx_audit::RiskTier {
    match risk {
        RiskTier::R1 => sweepx_audit::RiskTier::R1,
        RiskTier::R2 => sweepx_audit::RiskTier::R2,
        RiskTier::R3 => sweepx_audit::RiskTier::R3,
        RiskTier::R4 => sweepx_audit::RiskTier::R4,
        RiskTier::Blocked => unreachable!("blocked risk cannot enter an executable plan"),
    }
}

fn reconciliation_with_reason(
    mut record: ReconciliationRequired,
    reason: ReconciliationReason,
) -> ReconciliationRequired {
    record.reason = reason;
    record
}

fn reconciliation_error(
    record: ReconciliationRequired,
    reason: ReconciliationReason,
    completed: Vec<SimulatedActionReceipt>,
    authorization: ExecutionAuthorization,
) -> ExecutorError {
    ExecutorError::NeedsReconciliation {
        reconciliation: Box::new(reconciliation_with_reason(record, reason)),
        completed,
        authorization: Box::new(authorization),
    }
}

fn requested_mode(mode: DeletionMode) -> RequestedMode {
    match mode {
        DeletionMode::Trash => RequestedMode::Trash,
        DeletionMode::Permanent => RequestedMode::Permanent,
    }
}

#[cfg(test)]
mod tests;
