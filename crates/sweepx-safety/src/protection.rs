use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plan::DeletionMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionTargetKind {
    Root,
    MountOrShareRoot,
    Home,
    State,
    TrashInternal,
    ActiveCwdOrInstall,
    DeviceSocketOrFifo,
    UnknownReparseOrSpecial,
    OutsideScanRoot,
    UnreadOrNewDescendant,
    ProtectedMarkerModeledInput,
    Regular,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionTargetStatus {
    Known,
    Unknown,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionTarget {
    pub identity: String,
    pub kind: ProtectionTargetKind,
    pub status: ProtectionTargetStatus,
}

impl ProtectionTarget {
    pub fn regular(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            kind: ProtectionTargetKind::Regular,
            status: ProtectionTargetStatus::Known,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardProtectionReason {
    UnknownTarget,
    BlockedTarget,
    ProtectedRoot,
    ProtectedMountOrShareRoot,
    ProtectedHome,
    ProtectedState,
    ProtectedTrashInternal,
    ProtectedActiveCwdOrInstall,
    ProtectedDeviceSocketOrFifo,
    ProtectedUnknownReparseOrSpecial,
    ProtectedOutsideScanRoot,
    ProtectedUnreadOrNewDescendant,
    ProtectedMarkerModeledInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardProtectionDecision {
    Allow,
    Reject(HardProtectionReason),
}

#[derive(Debug, Clone, Default)]
pub struct HardProtectionPolicy;

impl HardProtectionPolicy {
    pub fn evaluate(&self, target: &ProtectionTarget) -> HardProtectionDecision {
        match target.status {
            ProtectionTargetStatus::Unknown => {
                return HardProtectionDecision::Reject(HardProtectionReason::UnknownTarget);
            }
            ProtectionTargetStatus::Blocked => {
                return HardProtectionDecision::Reject(HardProtectionReason::BlockedTarget);
            }
            ProtectionTargetStatus::Known => {}
        }

        match target.kind {
            ProtectionTargetKind::Root => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedRoot)
            }
            ProtectionTargetKind::MountOrShareRoot => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedMountOrShareRoot)
            }
            ProtectionTargetKind::Home => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedHome)
            }
            ProtectionTargetKind::State => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedState)
            }
            ProtectionTargetKind::TrashInternal => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedTrashInternal)
            }
            ProtectionTargetKind::ActiveCwdOrInstall => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedActiveCwdOrInstall)
            }
            ProtectionTargetKind::DeviceSocketOrFifo => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedDeviceSocketOrFifo)
            }
            ProtectionTargetKind::UnknownReparseOrSpecial => HardProtectionDecision::Reject(
                HardProtectionReason::ProtectedUnknownReparseOrSpecial,
            ),
            ProtectionTargetKind::OutsideScanRoot => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedOutsideScanRoot)
            }
            ProtectionTargetKind::UnreadOrNewDescendant => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedUnreadOrNewDescendant)
            }
            ProtectionTargetKind::ProtectedMarkerModeledInput => {
                HardProtectionDecision::Reject(HardProtectionReason::ProtectedMarkerModeledInput)
            }
            ProtectionTargetKind::Regular => HardProtectionDecision::Allow,
        }
    }

    pub fn require_mode(
        &self,
        mode: DeletionMode,
        requested_targets: &[ProtectionTarget],
    ) -> Result<(), ModePolicyError> {
        for target in requested_targets {
            if let HardProtectionDecision::Reject(reason) = self.evaluate(target) {
                return Err(ModePolicyError::HardBlocked {
                    mode,
                    target_identity: target.identity.clone(),
                    reason,
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModePolicyError {
    #[error("mode {mode:?} is hard blocked for target {target_identity}: {reason:?}")]
    HardBlocked {
        mode: DeletionMode,
        target_identity: String,
        reason: HardProtectionReason,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_and_blocked_targets() {
        let policy = HardProtectionPolicy;
        let unknown = ProtectionTarget {
            identity: "target-1".to_string(),
            kind: ProtectionTargetKind::Regular,
            status: ProtectionTargetStatus::Unknown,
        };
        let blocked = ProtectionTarget {
            identity: "target-2".to_string(),
            kind: ProtectionTargetKind::Regular,
            status: ProtectionTargetStatus::Blocked,
        };

        assert_eq!(
            policy.evaluate(&unknown),
            HardProtectionDecision::Reject(HardProtectionReason::UnknownTarget)
        );
        assert_eq!(
            policy.evaluate(&blocked),
            HardProtectionDecision::Reject(HardProtectionReason::BlockedTarget)
        );
    }

    #[test]
    fn rejects_builtin_protected_kinds() {
        let policy = HardProtectionPolicy;

        for kind in [
            ProtectionTargetKind::Root,
            ProtectionTargetKind::MountOrShareRoot,
            ProtectionTargetKind::Home,
            ProtectionTargetKind::State,
            ProtectionTargetKind::TrashInternal,
            ProtectionTargetKind::ActiveCwdOrInstall,
            ProtectionTargetKind::DeviceSocketOrFifo,
            ProtectionTargetKind::UnknownReparseOrSpecial,
            ProtectionTargetKind::OutsideScanRoot,
            ProtectionTargetKind::UnreadOrNewDescendant,
            ProtectionTargetKind::ProtectedMarkerModeledInput,
        ] {
            let decision = policy.evaluate(&ProtectionTarget {
                identity: format!("{kind:?}"),
                kind,
                status: ProtectionTargetStatus::Known,
            });
            assert!(matches!(decision, HardProtectionDecision::Reject(_)));
        }
    }
}
