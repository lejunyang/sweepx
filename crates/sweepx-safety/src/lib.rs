//! Safety foundation types for exact-plan authorization and preflight validation.
//!
//! ```compile_fail
//! let _plan: sweepx_safety::DeletionPlan = serde_json::from_str("{}").unwrap();
//! ```
//!
//! ```compile_fail
//! let _auth: sweepx_safety::ExecutionAuthorization = serde_json::from_str("{}").unwrap();
//! ```

mod authorization;
mod permit;
mod plan;
mod protection;
mod state;
mod time;

pub use authorization::{
    ApprovalConfirmationEvidence, AuthorizationBindError, AuthorizationClaimError,
    AuthorizationConsumeError, AuthorizationMatchError, AuthorizationState, ExecutionAuthorization,
    HumanApprovalRequest, PermanentAuthorizationRequest,
};
pub use permit::{
    PERMIT_TTL, PreflightPermit, PreflightPermitError, PreflightPermitRequest,
    consume_preflight_permit, issue_preflight_permit,
};
pub use plan::{
    AggregateRisk, CanonicalPlanError, DeletionMode, DeletionPlan, DeletionPlanInput,
    ExplanationDigest, ManifestDigest, PlanAction, PlanDigest, PlanFingerprint, PlanId, PlanItem,
    PlanItemDigest, PlanItemInput, RiskFactor, RiskTier, SelectedActionSet, TargetIdentity,
};
pub use protection::{
    HardProtectionDecision, HardProtectionPolicy, HardProtectionReason, ModePolicyError,
    ProtectionTarget, ProtectionTargetKind, ProtectionTargetStatus,
};
pub use state::{
    BatchState, BatchStateError, ItemState, ItemStateError, StateTransitionPolicy,
    default_batch_transition_policy, default_item_transition_policy, validate_batch_transition,
    validate_item_transition,
};
pub use time::{Clock, FixedClock, SystemClock};
