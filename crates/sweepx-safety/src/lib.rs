//! Safety foundation types for exact-plan authorization and preflight validation.
//!
//! ```compile_fail
//! let _plan: sweepx_safety::DeletionPlan = serde_json::from_str("{}").unwrap();
//! ```
//!
//! ```compile_fail
//! let _auth: sweepx_safety::ExecutionAuthorization = serde_json::from_str("{}").unwrap();
//! ```
//!
//! Real human and dangerous-delete authorization constructors are deliberately not public.
//! External P3 callers can mint only the explicitly simulation-only authorization type.
//!
//! ```compile_fail
//! use sweepx_safety::HumanApprovalRequest;
//! ```
//!
//! ```compile_fail
//! use sweepx_safety::PermanentAuthorizationRequest;
//! ```
//!
//! ```compile_fail
//! # fn assert_not_clone(token: sweepx_safety::ExecutionAuthorization) {
//! let _copy = token.clone();
//! # }
//! ```
//!
//! ```compile_fail
//! # fn assert_not_clone(token: sweepx_safety::ConsumedPreflightPermit) {
//! let _copy = token.clone();
//! # }
//! ```
//!
//! ```compile_fail
//! # fn assert_not_clone(proof: sweepx_safety::simulation::SimulatedRevalidationProof) {
//! let _copy = proof.clone();
//! # }
//! ```
//!
//! ```compile_fail
//! let _proof = sweepx_safety::simulation::SimulatedRevalidationProof {
//!     authorization_id: String::new(),
//! };
//! ```
//!
//! ```compile_fail
//! let _action: sweepx_safety::simulation::SimulatedAction =
//!     serde_json::from_str("{}").unwrap();
//! ```

mod authorization;
mod permit;
mod plan;
mod protection;
mod state;
mod time;

pub use authorization::{
    AuditBindingError, AuthorizationBindError, AuthorizationClaimError, AuthorizationConsumeError,
    AuthorizationMatchError, AuthorizationState, ExecutionAuthorization,
};
pub use permit::{
    ConsumedPermanentPreflightPermit, ConsumedPreflightPermit, ConsumedTrashPreflightPermit,
    PERMIT_TTL, PreflightPermit, PreflightPermitError, consume_preflight_permit,
};

pub mod simulation {
    pub use crate::authorization::SimulatedAuthorizationRequest;
    pub use crate::permit::{
        DeterministicRevalidationObserver, SimulatedRevalidationObserver,
        SimulatedRevalidationProof, issue_simulated_preflight_permit,
        verify_simulated_revalidation,
    };
    pub use crate::plan::SimulatedAction;
}
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
