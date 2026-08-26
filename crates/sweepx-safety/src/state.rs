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
    use super::*;

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
}
