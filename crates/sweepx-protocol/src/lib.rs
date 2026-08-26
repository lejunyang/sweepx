use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use sweepx_model::{OperationId, RequestId};

pub const OUTPUT_SCHEMA: &str = "sweepx.output/v1";
pub const EVENT_SCHEMA: &str = "sweepx.event/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OutputKind {
    #[serde(rename = "scan.result")]
    #[schemars(rename = "scan.result")]
    ScanResult,
    #[serde(rename = "explanation.result")]
    #[schemars(rename = "explanation.result")]
    ExplanationResult,
    #[serde(rename = "plan.result")]
    #[schemars(rename = "plan.result")]
    PlanResult,
    #[serde(rename = "execution.result")]
    #[schemars(rename = "execution.result")]
    ExecutionResult,
    #[serde(rename = "recovery.result")]
    #[schemars(rename = "recovery.result")]
    RecoveryResult,
    #[serde(rename = "cancel.result")]
    #[schemars(rename = "cancel.result")]
    CancelResult,
    #[serde(rename = "status.result")]
    #[schemars(rename = "status.result")]
    StatusResult,
    #[serde(rename = "capabilities.result")]
    #[schemars(rename = "capabilities.result")]
    CapabilitiesResult,
    #[serde(rename = "cleaner.result")]
    #[schemars(rename = "cleaner.result")]
    CleanerResult,
    #[serde(rename = "audit.result")]
    #[schemars(rename = "audit.result")]
    AuditResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutputStatus {
    Ok,
    Partial,
    Blocked,
    AuthorizationRequired,
    Stale,
    Failed,
    NeedsReconciliation,
    Cancelled,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, JsonSchema)]
#[repr(u8)]
pub enum ExitCode {
    Completed = 0,
    UsageError = 2,
    Unsupported = 3,
    Partial = 4,
    SafetyBlocked = 5,
    AuthorizationRequired = 6,
    StaleReplanRequired = 7,
    OperationFailed = 8,
    NeedsReconciliation = 9,
    Cancelled = 10,
    StateIntegrityUnavailable = 11,
    CleanerTrustOrCompat = 12,
    OfficialCommandFailed = 13,
}

impl Serialize for ExitCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for ExitCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(Self::Completed),
            2 => Ok(Self::UsageError),
            3 => Ok(Self::Unsupported),
            4 => Ok(Self::Partial),
            5 => Ok(Self::SafetyBlocked),
            6 => Ok(Self::AuthorizationRequired),
            7 => Ok(Self::StaleReplanRequired),
            8 => Ok(Self::OperationFailed),
            9 => Ok(Self::NeedsReconciliation),
            10 => Ok(Self::Cancelled),
            11 => Ok(Self::StateIntegrityUnavailable),
            12 => Ok(Self::CleanerTrustOrCompat),
            13 => Ok(Self::OfficialCommandFailed),
            value => Err(serde::de::Error::custom(format!(
                "unknown sweepx exit code: {value}"
            ))),
        }
    }
}

impl ExitCode {
    fn severity_rank(self) -> u8 {
        match self {
            Self::Completed => 0,
            Self::UsageError => 100,
            Self::Partial => 10,
            Self::Unsupported => 20,
            Self::OperationFailed => 30,
            Self::OfficialCommandFailed => 40,
            Self::CleanerTrustOrCompat => 50,
            Self::AuthorizationRequired => 60,
            Self::SafetyBlocked => 70,
            Self::StaleReplanRequired => 80,
            Self::Cancelled => 90,
            Self::NeedsReconciliation => 95,
            Self::StateIntegrityUnavailable => 99,
        }
    }

    pub fn more_conservative(self, other: Self) -> Self {
        if self.severity_rank() >= other.severity_rank() {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CompatSnapshot {
    pub core_version: String,
    pub scanner_semantics_version: u32,
    pub safety_policy_version: u32,
    pub platform_adapter: PlatformAdapterCompat,
    pub cleaner_set_digest: String,
    pub required_features: Vec<String>,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlatformAdapterCompat {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OutputEnvelope {
    pub schema: String,
    pub kind: OutputKind,
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub generated_at: String,
    pub status: OutputStatus,
    pub exit_code: ExitCode,
    pub compat: CompatSnapshot,
    pub summary: Value,
    pub data: Value,
    pub warnings: Vec<ProtocolMessage>,
    pub errors: Vec<ProtocolMessage>,
}

impl OutputEnvelope {
    pub fn new(
        kind: OutputKind,
        request_id: RequestId,
        operation_id: OperationId,
        generated_at: impl Into<String>,
        status: OutputStatus,
        exit_code: ExitCode,
        compat: CompatSnapshot,
    ) -> Self {
        Self {
            schema: OUTPUT_SCHEMA.to_string(),
            kind,
            request_id,
            operation_id,
            generated_at: generated_at.into(),
            status,
            exit_code,
            compat,
            summary: json!({}),
            data: json!({}),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn conservative_exit_code(&self) -> ExitCode {
        self.exit_code.more_conservative(self.status.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolMessage {
    pub code: String,
    pub class: String,
    pub message_key: String,
    pub retryable: bool,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventPhase {
    Detect,
    Analyze,
    Plan,
    Authorize,
    Revalidate,
    Execute,
    Reconcile,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EventType {
    #[serde(rename = "operation.started")]
    #[schemars(rename = "operation.started")]
    OperationStarted,
    #[serde(rename = "phase.changed")]
    #[schemars(rename = "phase.changed")]
    PhaseChanged,
    #[serde(rename = "scan.root.admitted")]
    #[schemars(rename = "scan.root.admitted")]
    ScanRootAdmitted,
    #[serde(rename = "scan.progress")]
    #[schemars(rename = "scan.progress")]
    ScanProgress,
    #[serde(rename = "scan.aggregate.revised")]
    #[schemars(rename = "scan.aggregate.revised")]
    ScanAggregateRevised,
    #[serde(rename = "scan.boundary.observed")]
    #[schemars(rename = "scan.boundary.observed")]
    ScanBoundaryObserved,
    #[serde(rename = "scan.error.observed")]
    #[schemars(rename = "scan.error.observed")]
    ScanErrorObserved,
    #[serde(rename = "scan.root.completed")]
    #[schemars(rename = "scan.root.completed")]
    ScanRootCompleted,
    #[serde(rename = "candidate.detected")]
    #[schemars(rename = "candidate.detected")]
    CandidateDetected,
    #[serde(rename = "analysis.completed")]
    #[schemars(rename = "analysis.completed")]
    AnalysisCompleted,
    #[serde(rename = "plan.created")]
    #[schemars(rename = "plan.created")]
    PlanCreated,
    #[serde(rename = "plan.rejected")]
    #[schemars(rename = "plan.rejected")]
    PlanRejected,
    #[serde(rename = "approval.requested")]
    #[schemars(rename = "approval.requested")]
    ApprovalRequested,
    #[serde(rename = "approval.granted")]
    #[schemars(rename = "approval.granted")]
    ApprovalGranted,
    #[serde(rename = "approval.rejected")]
    #[schemars(rename = "approval.rejected")]
    ApprovalRejected,
    #[serde(rename = "approval.expired")]
    #[schemars(rename = "approval.expired")]
    ApprovalExpired,
    #[serde(rename = "authorization.explicit_dangerous_delete")]
    #[schemars(rename = "authorization.explicit_dangerous_delete")]
    AuthorizationExplicitDangerousDelete,
    #[serde(rename = "revalidation.started")]
    #[schemars(rename = "revalidation.started")]
    RevalidationStarted,
    #[serde(rename = "revalidation.passed")]
    #[schemars(rename = "revalidation.passed")]
    RevalidationPassed,
    #[serde(rename = "revalidation.stale")]
    #[schemars(rename = "revalidation.stale")]
    RevalidationStale,
    #[serde(rename = "preflight.ready")]
    #[schemars(rename = "preflight.ready")]
    PreflightReady,
    #[serde(rename = "hard_protection.blocked")]
    #[schemars(rename = "hard_protection.blocked")]
    HardProtectionBlocked,
    #[serde(rename = "operation.cancel.requested")]
    #[schemars(rename = "operation.cancel.requested")]
    OperationCancelRequested,
    #[serde(rename = "operation.cancel.accepted")]
    #[schemars(rename = "operation.cancel.accepted")]
    OperationCancelAccepted,
    #[serde(rename = "operation.cancel.already_requested")]
    #[schemars(rename = "operation.cancel.already_requested")]
    OperationCancelAlreadyRequested,
    #[serde(rename = "operation.cancel.already_terminal")]
    #[schemars(rename = "operation.cancel.already_terminal")]
    OperationCancelAlreadyTerminal,
    #[serde(rename = "operation.cancel.too_late")]
    #[schemars(rename = "operation.cancel.too_late")]
    OperationCancelTooLate,
    #[serde(rename = "action.intent.durable")]
    #[schemars(rename = "action.intent.durable")]
    ActionIntentDurable,
    #[serde(rename = "action.platform.completed")]
    #[schemars(rename = "action.platform.completed")]
    ActionPlatformCompleted,
    #[serde(rename = "action.skipped")]
    #[schemars(rename = "action.skipped")]
    ActionSkipped,
    #[serde(rename = "action.failed_before_submit")]
    #[schemars(rename = "action.failed_before_submit")]
    ActionFailedBeforeSubmit,
    #[serde(rename = "action.permit.consumed")]
    #[schemars(rename = "action.permit.consumed")]
    ActionPermitConsumed,
    #[serde(rename = "action.reconciled")]
    #[schemars(rename = "action.reconciled")]
    ActionReconciled,
    #[serde(rename = "action.indeterminate")]
    #[schemars(rename = "action.indeterminate")]
    ActionIndeterminate,
    #[serde(rename = "item.completed")]
    #[schemars(rename = "item.completed")]
    ItemCompleted,
    #[serde(rename = "batch.completed")]
    #[schemars(rename = "batch.completed")]
    BatchCompleted,
    #[serde(rename = "batch.partial")]
    #[schemars(rename = "batch.partial")]
    BatchPartial,
    #[serde(rename = "batch.cancelled")]
    #[schemars(rename = "batch.cancelled")]
    BatchCancelled,
    #[serde(rename = "batch.needs_reconciliation")]
    #[schemars(rename = "batch.needs_reconciliation")]
    BatchNeedsReconciliation,
    #[serde(rename = "recovery.started")]
    #[schemars(rename = "recovery.started")]
    RecoveryStarted,
    #[serde(rename = "recovery.completed")]
    #[schemars(rename = "recovery.completed")]
    RecoveryCompleted,
    #[serde(rename = "audit.started")]
    #[schemars(rename = "audit.started")]
    AuditStarted,
    #[serde(rename = "audit.batch.committed")]
    #[schemars(rename = "audit.batch.committed")]
    AuditBatchCommitted,
    #[serde(rename = "audit.failed")]
    #[schemars(rename = "audit.failed")]
    AuditFailed,
    #[serde(rename = "detail.persistence.failed")]
    #[schemars(rename = "detail.persistence.failed")]
    DetailPersistenceFailed,
    #[serde(rename = "stream.reset_required")]
    #[schemars(rename = "stream.reset_required")]
    StreamResetRequired,
    #[serde(rename = "operation.terminal")]
    #[schemars(rename = "operation.terminal")]
    OperationTerminal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    pub schema: String,
    pub stream_id: String,
    pub operation_id: OperationId,
    pub sequence: String,
    pub cursor: String,
    pub emitted_at: String,
    pub monotonic_offset_ns: String,
    pub r#type: EventType,
    pub phase: EventPhase,
    pub payload: Value,
    pub terminal: bool,
    pub checkpoint: EventCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EventCheckpoint {
    pub durable: bool,
    pub last_durable_sequence: String,
}

impl EventEnvelope {
    pub fn is_terminal_type(&self) -> bool {
        matches!(self.r#type, EventType::OperationTerminal)
    }
}

impl From<OutputStatus> for ExitCode {
    fn from(value: OutputStatus) -> Self {
        match value {
            OutputStatus::Ok => ExitCode::Completed,
            OutputStatus::Partial => ExitCode::Partial,
            OutputStatus::Blocked => ExitCode::SafetyBlocked,
            OutputStatus::AuthorizationRequired => ExitCode::AuthorizationRequired,
            OutputStatus::Stale => ExitCode::StaleReplanRequired,
            OutputStatus::Failed => ExitCode::OperationFailed,
            OutputStatus::NeedsReconciliation => ExitCode::NeedsReconciliation,
            OutputStatus::Cancelled => ExitCode::Cancelled,
            OutputStatus::Unsupported => ExitCode::Unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compat() -> CompatSnapshot {
        CompatSnapshot {
            core_version: "0.1.0".to_string(),
            scanner_semantics_version: 1,
            safety_policy_version: 1,
            platform_adapter: PlatformAdapterCompat {
                id: "test".to_string(),
                version: "0.1.0".to_string(),
            },
            cleaner_set_digest: "sha256:test".to_string(),
            required_features: vec![],
            extensions: vec![],
        }
    }

    #[test]
    fn output_status_maps_to_expected_exit_code() {
        assert_eq!(ExitCode::from(OutputStatus::Ok), ExitCode::Completed);
        assert_eq!(
            ExitCode::from(OutputStatus::AuthorizationRequired),
            ExitCode::AuthorizationRequired
        );
        assert_eq!(
            ExitCode::from(OutputStatus::NeedsReconciliation),
            ExitCode::NeedsReconciliation
        );
    }

    #[test]
    fn exit_precedence_prefers_more_conservative_meaning() {
        assert_eq!(
            ExitCode::Cancelled.more_conservative(ExitCode::NeedsReconciliation),
            ExitCode::NeedsReconciliation
        );
        assert_eq!(
            ExitCode::Partial.more_conservative(ExitCode::OperationFailed),
            ExitCode::OperationFailed
        );
        assert_eq!(
            ExitCode::Unsupported.more_conservative(ExitCode::Completed),
            ExitCode::Unsupported
        );
    }

    #[test]
    fn output_envelope_conservative_exit_code_uses_status_when_stronger() {
        let envelope = OutputEnvelope::new(
            OutputKind::ExecutionResult,
            RequestId::new("req-1"),
            OperationId::new("op-1"),
            "2026-08-26T00:00:00Z",
            OutputStatus::NeedsReconciliation,
            ExitCode::Cancelled,
            compat(),
        );
        assert_eq!(
            envelope.conservative_exit_code(),
            ExitCode::NeedsReconciliation
        );
    }

    #[test]
    fn event_envelope_marks_terminal_only_for_terminal_event_type() {
        let terminal = EventEnvelope {
            schema: EVENT_SCHEMA.to_string(),
            stream_id: "stream-1".to_string(),
            operation_id: OperationId::new("op-1"),
            sequence: "42".to_string(),
            cursor: "cursor".to_string(),
            emitted_at: "2026-08-26T00:00:00Z".to_string(),
            monotonic_offset_ns: "1234".to_string(),
            r#type: EventType::OperationTerminal,
            phase: EventPhase::Audit,
            payload: json!({ "status": "ok" }),
            terminal: true,
            checkpoint: EventCheckpoint {
                durable: true,
                last_durable_sequence: "42".to_string(),
            },
        };
        assert!(terminal.is_terminal_type());

        let non_terminal = EventEnvelope {
            r#type: EventType::ScanProgress,
            terminal: false,
            ..terminal
        };
        assert!(!non_terminal.is_terminal_type());
    }

    #[test]
    fn protocol_envelopes_serialize_with_stable_schema_names() {
        let envelope = OutputEnvelope::new(
            OutputKind::StatusResult,
            RequestId::new("req-1"),
            OperationId::new("op-1"),
            "2026-08-26T00:00:00Z",
            OutputStatus::Ok,
            ExitCode::Completed,
            compat(),
        );

        let encoded = serde_json::to_value(envelope).unwrap();
        assert_eq!(encoded["schema"], OUTPUT_SCHEMA);
        assert_eq!(encoded["kind"], "status.result");
        assert_eq!(encoded["status"], "ok");
        assert_eq!(encoded["exitCode"], 0);
        assert_eq!(encoded["requestId"], "req-1");
        assert!(encoded.get("request_id").is_none());
    }

    #[test]
    fn event_types_use_the_frozen_dotted_wire_names() {
        assert_eq!(
            serde_json::to_value(EventType::OperationStarted).unwrap(),
            json!("operation.started")
        );
        assert_eq!(
            serde_json::to_value(EventType::OperationTerminal).unwrap(),
            json!("operation.terminal")
        );
    }

    #[test]
    fn exit_precedence_matches_the_normative_order() {
        let order = [
            ExitCode::StateIntegrityUnavailable,
            ExitCode::NeedsReconciliation,
            ExitCode::Cancelled,
            ExitCode::StaleReplanRequired,
            ExitCode::SafetyBlocked,
            ExitCode::AuthorizationRequired,
            ExitCode::CleanerTrustOrCompat,
            ExitCode::OfficialCommandFailed,
            ExitCode::OperationFailed,
            ExitCode::Unsupported,
            ExitCode::Partial,
            ExitCode::Completed,
        ];
        for pair in order.windows(2) {
            assert_eq!(pair[0].more_conservative(pair[1]), pair[0]);
        }
    }
}
