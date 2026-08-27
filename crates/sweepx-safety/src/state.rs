use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BatchState {
    Discovered,
    Explained,
    Planned,
    AuthorizationPending,
    Authorized,
    Revalidating,
    Ready,
    Executing,
    Completed,
    Partial,
    Cancelled,
    NeedsReconciliation,
    Rejected,
    HardBlocked,
    Audited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemState {
    Candidate,
    Explained,
    InPlan,
    Authorized,
    Revalidating,
    PreflightReady,
    Trashing,
    PermanentDeleting,
    Succeeded,
    Failed,
    Skipped,
    Stale,
    Cancelled,
    Indeterminate,
    Rejected,
    HardBlocked,
    Audited,
}

pub type StateTransitionPolicy<S> = BTreeMap<S, BTreeSet<S>>;

pub fn default_batch_transition_policy() -> StateTransitionPolicy<BatchState> {
    use BatchState::*;
    map([
        (Discovered, set([Explained, Rejected, HardBlocked])),
        (Explained, set([Planned, Rejected, HardBlocked])),
        (Planned, set([AuthorizationPending, Rejected, HardBlocked])),
        (
            AuthorizationPending,
            set([Authorized, Rejected, HardBlocked]),
        ),
        (Authorized, set([Revalidating, Rejected, HardBlocked])),
        (
            Revalidating,
            set([Ready, Rejected, HardBlocked, NeedsReconciliation]),
        ),
        (Ready, set([Executing, Cancelled, HardBlocked])),
        (
            Executing,
            set([Completed, Partial, Cancelled, NeedsReconciliation]),
        ),
        (Completed, set([Audited])),
        (Partial, set([Audited])),
        (Cancelled, set([Audited, NeedsReconciliation])),
        (NeedsReconciliation, set([Audited, Partial, Completed])),
        (Rejected, set([Audited])),
        (HardBlocked, set([Audited])),
    ])
}

pub fn default_item_transition_policy() -> StateTransitionPolicy<ItemState> {
    use ItemState::*;
    map([
        (Candidate, set([Explained, Rejected, HardBlocked])),
        (Explained, set([InPlan, Rejected, HardBlocked])),
        (InPlan, set([Authorized, Rejected, HardBlocked])),
        (
            Authorized,
            set([Revalidating, Rejected, HardBlocked, Stale]),
        ),
        (
            Revalidating,
            set([PreflightReady, Skipped, Stale, Cancelled, HardBlocked]),
        ),
        (
            PreflightReady,
            set([Trashing, PermanentDeleting, Skipped, Cancelled, HardBlocked]),
        ),
        (Trashing, set([Succeeded, Failed, Indeterminate, Cancelled])),
        (
            PermanentDeleting,
            set([Succeeded, Failed, Indeterminate, Cancelled]),
        ),
        (Succeeded, set([Audited])),
        (Failed, set([Audited])),
        (Skipped, set([Audited])),
        (Stale, set([Audited])),
        (Cancelled, set([Audited])),
        (Indeterminate, set([Audited])),
        (Rejected, set([Audited])),
        (HardBlocked, set([Audited])),
    ])
}

pub fn validate_batch_transition(
    from: BatchState,
    to: BatchState,
    policy: &StateTransitionPolicy<BatchState>,
) -> Result<(), BatchStateError> {
    validate_transition(from, to, policy)
        .map_err(|_| BatchStateError::InvalidTransition { from, to })
}

pub fn validate_item_transition(
    from: ItemState,
    to: ItemState,
    policy: &StateTransitionPolicy<ItemState>,
) -> Result<(), ItemStateError> {
    validate_transition(from, to, policy)
        .map_err(|_| ItemStateError::InvalidTransition { from, to })
}

fn validate_transition<S>(from: S, to: S, policy: &StateTransitionPolicy<S>) -> Result<(), ()>
where
    S: Copy + Ord,
{
    match policy.get(&from) {
        Some(targets) if targets.contains(&to) => Ok(()),
        _ => Err(()),
    }
}

fn map<S, const N: usize>(entries: [(S, BTreeSet<S>); N]) -> BTreeMap<S, BTreeSet<S>>
where
    S: Ord,
{
    entries.into_iter().collect()
}

fn set<S, const N: usize>(entries: [S; N]) -> BTreeSet<S>
where
    S: Ord,
{
    entries.into_iter().collect()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BatchStateError {
    #[error("invalid batch transition from {from:?} to {to:?}")]
    InvalidTransition { from: BatchState, to: BatchState },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ItemStateError {
    #[error("invalid item transition from {from:?} to {to:?}")]
    InvalidTransition { from: ItemState, to: ItemState },
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct PolicyTransitions {
        batch: Vec<PolicyEdge>,
        item: Vec<PolicyEdge>,
    }

    #[derive(Debug, Deserialize)]
    struct PolicyEdge {
        from: String,
        to: Vec<String>,
    }

    fn policy_transitions() -> PolicyTransitions {
        serde_json::from_str(include_str!("../../../policy/state-transitions.json"))
            .expect("valid state transition policy json")
    }

    fn batch_policy_from_json() -> BTreeMap<String, BTreeSet<String>> {
        policy_transitions()
            .batch
            .into_iter()
            .map(|edge| (edge.from, edge.to.into_iter().collect()))
            .collect()
    }

    fn item_policy_from_json() -> BTreeMap<String, BTreeSet<String>> {
        policy_transitions()
            .item
            .into_iter()
            .map(|edge| (edge.from, edge.to.into_iter().collect()))
            .collect()
    }

    fn batch_policy_from_rust() -> BTreeMap<String, BTreeSet<String>> {
        default_batch_transition_policy()
            .into_iter()
            .map(|(from, to)| {
                (
                    batch_state_name(from).to_string(),
                    to.into_iter()
                        .map(batch_state_name)
                        .map(str::to_string)
                        .collect(),
                )
            })
            .collect()
    }

    fn item_policy_from_rust() -> BTreeMap<String, BTreeSet<String>> {
        default_item_transition_policy()
            .into_iter()
            .map(|(from, to)| {
                (
                    item_state_name(from).to_string(),
                    to.into_iter()
                        .map(item_state_name)
                        .map(str::to_string)
                        .collect(),
                )
            })
            .collect()
    }

    fn batch_state_name(state: BatchState) -> &'static str {
        match state {
            BatchState::Discovered => "DISCOVERED",
            BatchState::Explained => "EXPLAINED",
            BatchState::Planned => "PLANNED",
            BatchState::AuthorizationPending => "AUTHORIZATION_PENDING",
            BatchState::Authorized => "AUTHORIZED",
            BatchState::Revalidating => "REVALIDATING",
            BatchState::Ready => "READY",
            BatchState::Executing => "EXECUTING",
            BatchState::Completed => "COMPLETED",
            BatchState::Partial => "PARTIAL",
            BatchState::Cancelled => "CANCELLED",
            BatchState::NeedsReconciliation => "NEEDS_RECONCILIATION",
            BatchState::Rejected => "REJECTED",
            BatchState::HardBlocked => "HARD_BLOCKED",
            BatchState::Audited => "AUDITED",
        }
    }

    fn item_state_name(state: ItemState) -> &'static str {
        match state {
            ItemState::Candidate => "CANDIDATE",
            ItemState::Explained => "EXPLAINED",
            ItemState::InPlan => "IN_PLAN",
            ItemState::Authorized => "AUTHORIZED",
            ItemState::Revalidating => "REVALIDATING",
            ItemState::PreflightReady => "PREFLIGHT_READY",
            ItemState::Trashing => "TRASHING",
            ItemState::PermanentDeleting => "PERMANENT_DELETING",
            ItemState::Succeeded => "SUCCEEDED",
            ItemState::Failed => "FAILED",
            ItemState::Skipped => "SKIPPED",
            ItemState::Stale => "STALE",
            ItemState::Cancelled => "CANCELLED",
            ItemState::Indeterminate => "INDETERMINATE",
            ItemState::Rejected => "REJECTED",
            ItemState::HardBlocked => "HARD_BLOCKED",
            ItemState::Audited => "AUDITED",
        }
    }

    fn can_reach(
        start: ItemState,
        goal: ItemState,
        policy: &StateTransitionPolicy<ItemState>,
    ) -> bool {
        let mut visited = BTreeSet::new();
        let mut frontier = VecDeque::from([start]);

        while let Some(current) = frontier.pop_front() {
            if current == goal {
                return true;
            }
            if !visited.insert(current) {
                continue;
            }
            if let Some(next) = policy.get(&current) {
                frontier.extend(next.iter().copied());
            }
        }

        false
    }

    #[test]
    fn batch_policy_rejects_invalid_edges() {
        let policy = default_batch_transition_policy();
        assert!(
            validate_batch_transition(BatchState::Ready, BatchState::Executing, &policy).is_ok()
        );
        assert_eq!(
            validate_batch_transition(BatchState::Ready, BatchState::Completed, &policy)
                .unwrap_err(),
            BatchStateError::InvalidTransition {
                from: BatchState::Ready,
                to: BatchState::Completed,
            }
        );
    }

    #[test]
    fn item_policy_rejects_invalid_edges() {
        let policy = default_item_transition_policy();
        assert!(
            validate_item_transition(
                ItemState::PreflightReady,
                ItemState::PermanentDeleting,
                &policy
            )
            .is_ok()
        );
        assert_eq!(
            validate_item_transition(ItemState::Candidate, ItemState::Succeeded, &policy)
                .unwrap_err(),
            ItemStateError::InvalidTransition {
                from: ItemState::Candidate,
                to: ItemState::Succeeded,
            }
        );
    }

    #[test]
    fn policy_json_and_rust_batch_transition_tables_stay_in_parity() {
        assert_eq!(batch_policy_from_rust(), batch_policy_from_json());
    }

    #[test]
    fn policy_json_and_rust_item_transition_tables_stay_in_parity() {
        assert_eq!(item_policy_from_rust(), item_policy_from_json());
    }

    #[test]
    fn trash_failure_unsupported_denied_cancelled_and_ambiguous_outcomes_cannot_transition_to_permanent()
     {
        let policy = default_item_transition_policy();
        for outcome in [
            ItemState::Failed,
            ItemState::Skipped,
            ItemState::Rejected,
            ItemState::Cancelled,
            ItemState::Indeterminate,
            ItemState::HardBlocked,
            ItemState::Stale,
        ] {
            assert_eq!(
                validate_item_transition(outcome, ItemState::PermanentDeleting, &policy)
                    .unwrap_err(),
                ItemStateError::InvalidTransition {
                    from: outcome,
                    to: ItemState::PermanentDeleting,
                }
            );
        }
    }

    #[test]
    fn trash_failure_unsupported_denied_cancelled_and_ambiguous_outcomes_cannot_dispatch_to_permanent()
     {
        let policy = default_item_transition_policy();
        for outcome in [
            ItemState::Failed,
            ItemState::Skipped,
            ItemState::Rejected,
            ItemState::Cancelled,
            ItemState::Indeterminate,
            ItemState::HardBlocked,
            ItemState::Stale,
        ] {
            assert!(
                !can_reach(outcome, ItemState::PermanentDeleting, &policy),
                "{outcome:?} unexpectedly reaches PermanentDeleting"
            );
        }
    }

    #[test]
    fn permanent_dispatch_is_only_available_from_preflight_ready() {
        let policy = default_item_transition_policy();
        for state in [
            ItemState::Candidate,
            ItemState::Explained,
            ItemState::InPlan,
            ItemState::Authorized,
            ItemState::Revalidating,
            ItemState::Trashing,
            ItemState::PermanentDeleting,
            ItemState::Succeeded,
            ItemState::Failed,
            ItemState::Skipped,
            ItemState::Stale,
            ItemState::Cancelled,
            ItemState::Indeterminate,
            ItemState::Rejected,
            ItemState::HardBlocked,
            ItemState::Audited,
        ] {
            assert!(
                validate_item_transition(state, ItemState::PermanentDeleting, &policy).is_err(),
                "{state:?} unexpectedly dispatches to PermanentDeleting"
            );
        }
        assert!(
            validate_item_transition(
                ItemState::PreflightReady,
                ItemState::PermanentDeleting,
                &policy
            )
            .is_ok()
        );
    }
}
