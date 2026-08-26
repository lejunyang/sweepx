use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SNAPSHOT_FILE: &str = "audit.snapshot";
const ANCHOR_FILE: &str = "audit.anchor";
const LOCK_FILE: &str = "audit.lock";
const RECORD_DOMAIN: &str = "SweepX audit simulated v3\0";
const PATH_HASH_DOMAIN: &str = "SweepX native path hash v1\0";
const SNAPSHOT_VERSION: &str = "sweepx.audit.snapshot.v1";
const ANCHOR_VERSION: &str = "sweepx.audit.anchor.v1";
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ANCHOR_BYTES: usize = 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024;
const MAX_NOTES: usize = 16;
const MAX_NOTE_BYTES: usize = 512;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_POLICY_VERSION_BYTES: usize = 512;
const MAX_BINDING_ACTIONS: usize = 1_024;
const MAX_BINDING_ITEMS: usize = 1_024;
const MAX_EVENTS: usize = 8_192;
const MAX_AUTHORIZATIONS: usize = 128;
const MAX_INTENTS: usize = 4_096;
const MAX_EVENT_COMMIT_GROWTH: usize = 2 * MAX_EVENT_BYTES + 2_048;
static TEMP_ORDINAL: AtomicU64 = AtomicU64::new(0);

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let parsed = value.parse::<u64>().map_err(serde::de::Error::custom)?;
        if parsed.to_string() != value {
            return Err(serde::de::Error::custom("non-canonical decimal u64"));
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
struct StableId(String);

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        validate_stable_id(&value, "persisted_stable_id").map_err(serde::de::Error::custom)?;
        Ok(Self(value))
    }
}

impl StableId {
    fn new(value: impl Into<String>, field: &'static str) -> Result<Self, AuditError> {
        let value = value.into();
        validate_stable_id(&value, field)?;
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! id_type {
    ($name:ident, $field:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(StableId);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AuditError> {
                Ok(Self(StableId::new(value, $field)?))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

id_type!(BatchId, "batch_id");
id_type!(AuthorizationId, "authorization_id");
id_type!(PlanId, "plan_id");
id_type!(ItemId, "item_id");
id_type!(ActionId, "action_id");
id_type!(AttemptId, "attempt_id");
id_type!(NonceId, "nonce");
id_type!(DigestString, "digest");
id_type!(HostId, "host_id");
id_type!(UserId, "user_id");
id_type!(SessionId, "session_id");
id_type!(PathHash, "path_hash");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationSource {
    HumanApproval,
    ExplicitDangerousDelete,
    DeterministicSimulation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedMode {
    Trash,
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    R1,
    R2,
    R3,
    R4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum AuthorizationState {
    Unused,
    Claimed {
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
    },
    Consumed {
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IntentTerminalState {
    Reserved,
    IndeterminateRecorded,
    OutcomeRecorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StableStatus {
    TrashSucceededPlatformReported,
    TrashSucceededLocationReported,
    PermanentDeleteSucceeded,
    FailedPlatformError,
    FailedCancelledByPlatform,
    FailedSourceUnchanged,
    VanishedBeforeAction,
    CancelledBeforeAction,
    IndeterminateAfterCrash,
    IndeterminatePlatformResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    PlatformTrashReported,
    TrashLocationReported,
    InapplicablePermanent,
    FailedSourceUnchanged,
    CancelledBeforeAction,
    VanishedBeforeAction,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDisposition {
    Pending,
    Reserved,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationBinding {
    pub authorization_id: AuthorizationId,
    pub authorization_source: AuthorizationSource,
    pub batch_id: BatchId,
    pub plan_id: PlanId,
    pub plan_digest: DigestString,
    pub requested_mode: RequestedMode,
    pub item_ids: BTreeSet<ItemId>,
    pub action_ids: BTreeSet<ActionId>,
    pub item_by_action: BTreeMap<ActionId, ItemId>,
    #[serde(with = "decimal_u64")]
    pub action_count: u64,
    pub risk_by_action: BTreeMap<ActionId, RiskTier>,
    pub policy_version: String,
    pub policy_digest: DigestString,
    pub protected_anchor_snapshot_digest: DigestString,
    pub adapter_capabilities_digest: DigestString,
    pub cleaner_set_digest: DigestString,
    pub host_instance_id: HostId,
    pub user_identity: UserId,
    pub workflow_session: SessionId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRecord {
    binding: AuthorizationBinding,
    state: AuthorizationState,
}

pub struct ClaimedExecution {
    binding: AuthorizationBinding,
    fence_epoch: u64,
    store_root: PathBuf,
    batch_lock: File,
    session_active: Arc<AtomicBool>,
    mutation_lock: Arc<Mutex<()>>,
    owner_pid: u32,
}

impl std::fmt::Debug for ClaimedExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaimedExecution")
            .field("authorization_id", &self.binding.authorization_id)
            .field("batch_id", &self.binding.batch_id)
            .field("fence_epoch", &self.fence_epoch)
            .finish_non_exhaustive()
    }
}

impl ClaimedExecution {
    pub fn binding(&self) -> &AuthorizationBinding {
        &self.binding
    }

    pub fn authorization_id(&self) -> &AuthorizationId {
        &self.binding.authorization_id
    }

    pub fn batch_id(&self) -> &BatchId {
        &self.binding.batch_id
    }

    pub fn plan_id(&self) -> &PlanId {
        &self.binding.plan_id
    }

    pub fn plan_digest(&self) -> &DigestString {
        &self.binding.plan_digest
    }

    pub fn requested_mode(&self) -> RequestedMode {
        self.binding.requested_mode
    }

    pub fn fence_epoch(&self) -> u64 {
        self.fence_epoch
    }

    pub fn authorization_source(&self) -> AuthorizationSource {
        self.binding.authorization_source
    }

    pub fn risk_for_action(&self, action_id: &ActionId) -> Option<RiskTier> {
        self.binding.risk_by_action.get(action_id).copied()
    }

    pub fn validate_current_process(&self) -> Result<(), AuditError> {
        if self.owner_pid != std::process::id() {
            return Err(AuditError::ForkedProcess);
        }
        Ok(())
    }

    fn validates_store(&self, root: &Path) -> bool {
        self.store_root == root
    }

    fn lock_mutation(&self) -> Result<MutexGuard<'_, ()>, AuditError> {
        if self.owner_pid != std::process::id() {
            return Err(AuditError::ForkedProcess);
        }
        self.mutation_lock
            .lock()
            .map_err(|_| AuditError::SessionLockPoisoned)
    }
}

impl Drop for ClaimedExecution {
    fn drop(&mut self) {
        if self.owner_pid != std::process::id() {
            return;
        }
        let _guard = self
            .mutation_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = FileExt::unlock(&self.batch_lock);
        self.session_active.store(false, Ordering::Release);
    }
}

#[derive(PartialEq, Eq)]
pub struct DurableIntentToken {
    attempt_id: AttemptId,
    nonce: NonceId,
    authorization_id: AuthorizationId,
    batch_id: BatchId,
    plan_id: PlanId,
    plan_digest: DigestString,
    item_id: ItemId,
    action_id: ActionId,
    requested_mode: RequestedMode,
    risk_tier: RiskTier,
    source_path_hash: PathHash,
    before_revalidation_digest: DigestString,
    fence_epoch: u64,
    creator_pid: u32,
}

impl std::fmt::Debug for DurableIntentToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableIntentToken")
            .field("attempt_id", &self.attempt_id)
            .field("authorization_id", &self.authorization_id)
            .field("batch_id", &self.batch_id)
            .field("plan_id", &self.plan_id)
            .field("item_id", &self.item_id)
            .field("action_id", &self.action_id)
            .field("requested_mode", &self.requested_mode)
            .field("risk_tier", &self.risk_tier)
            .field("fence_epoch", &self.fence_epoch)
            .finish_non_exhaustive()
    }
}

/// The result of reserving an action exactly once.
///
/// Only `Created` carries execution authority. Existing reservations expose diagnostics without
/// the nonce-bearing token, so a repeated lookup cannot mint a second one-shot permit.
///
/// ```compile_fail
/// use sweepx_audit::{DurableIntentToken, IntentReservation};
/// fn replay(reservation: IntentReservation) -> DurableIntentToken {
///     match reservation {
///         IntentReservation::Created(token) => token,
///         IntentReservation::Existing(info) | IntentReservation::Conflicting(info) => info,
///     }
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum IntentReservation {
    Created(DurableIntentToken),
    Existing(IntentReservationInfo),
    Conflicting(IntentReservationInfo),
}

impl IntentReservation {
    fn into_legacy_result(self) -> Result<DurableIntentToken, AuditError> {
        match self {
            Self::Created(token) => Ok(token),
            Self::Existing(info) | Self::Conflicting(info) => Err(
                AuditError::ActionAlreadyReserved(info.action_id().as_str().to_string()),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentReservationInfo {
    attempt_id: AttemptId,
    item_id: ItemId,
    action_id: ActionId,
}

impl IntentReservationInfo {
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }

    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }
}

impl DurableIntentToken {
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }

    pub fn nonce(&self) -> &NonceId {
        &self.nonce
    }

    pub fn authorization_id(&self) -> &AuthorizationId {
        &self.authorization_id
    }

    pub fn batch_id(&self) -> &BatchId {
        &self.batch_id
    }

    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    pub fn plan_digest(&self) -> &DigestString {
        &self.plan_digest
    }

    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    pub fn item_id(&self) -> &ItemId {
        &self.item_id
    }

    pub fn requested_mode(&self) -> RequestedMode {
        self.requested_mode
    }

    pub fn risk_tier(&self) -> RiskTier {
        self.risk_tier
    }

    pub fn source_path_hash(&self) -> &PathHash {
        &self.source_path_hash
    }

    pub fn before_revalidation_digest(&self) -> &DigestString {
        &self.before_revalidation_digest
    }

    pub fn fence_epoch(&self) -> u64 {
        self.fence_epoch
    }

    pub fn validate_current_process(&self) -> Result<(), AuditError> {
        if self.creator_pid != std::process::id() {
            return Err(AuditError::ForkedProcess);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentAuthority {
    attempt_id: AttemptId,
    nonce: NonceId,
    authorization_id: AuthorizationId,
    batch_id: BatchId,
    plan_id: PlanId,
    plan_digest: DigestString,
    item_id: ItemId,
    action_id: ActionId,
    requested_mode: RequestedMode,
    risk_tier: RiskTier,
    source_path_hash: PathHash,
    before_revalidation_digest: DigestString,
    #[serde(with = "decimal_u64")]
    fence_epoch: u64,
    #[serde(with = "decimal_u64")]
    attempt_ordinal: u64,
    terminal_state: IntentTerminalState,
}

impl IntentAuthority {
    fn as_token(&self) -> DurableIntentToken {
        DurableIntentToken {
            attempt_id: self.attempt_id.clone(),
            nonce: self.nonce.clone(),
            authorization_id: self.authorization_id.clone(),
            batch_id: self.batch_id.clone(),
            plan_id: self.plan_id.clone(),
            plan_digest: self.plan_digest.clone(),
            item_id: self.item_id.clone(),
            action_id: self.action_id.clone(),
            requested_mode: self.requested_mode,
            risk_tier: self.risk_tier,
            source_path_hash: self.source_path_hash.clone(),
            before_revalidation_digest: self.before_revalidation_digest.clone(),
            fence_epoch: self.fence_epoch,
            creator_pid: std::process::id(),
        }
    }

    fn reservation_info(&self) -> IntentReservationInfo {
        IntentReservationInfo {
            attempt_id: self.attempt_id.clone(),
            item_id: self.item_id.clone(),
            action_id: self.action_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Projection {
    #[serde(with = "decimal_u64")]
    latest_fence_epoch: u64,
    #[serde(with = "decimal_u64")]
    next_attempt_ordinal: u64,
    authorizations: BTreeMap<AuthorizationId, AuthorizationRecord>,
    intents: BTreeMap<AttemptId, IntentAuthority>,
    outcomes: BTreeMap<AttemptId, OutcomeEvent>,
    recoveries: BTreeMap<AttemptId, RecoveryRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFile {
    version: String,
    projection: Projection,
    events: Vec<JournalRecord>,
    head: ChainHead,
}

impl Default for SnapshotFile {
    fn default() -> Self {
        Self {
            version: SNAPSHOT_VERSION.to_string(),
            projection: Projection::default(),
            events: Vec::new(),
            head: ChainHead::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ChainHead {
    #[serde(with = "decimal_u64")]
    latest_sequence: u64,
    latest_digest: Option<String>,
    #[serde(with = "decimal_u64")]
    action_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableAnchor {
    version: String,
    #[serde(with = "decimal_u64")]
    latest_sequence: u64,
    latest_digest: Option<String>,
    #[serde(with = "decimal_u64")]
    action_sequence: u64,
}

impl Default for DurableAnchor {
    fn default() -> Self {
        Self {
            version: ANCHOR_VERSION.to_string(),
            latest_sequence: 0,
            latest_digest: None,
            action_sequence: 0,
        }
    }
}

impl From<&ChainHead> for DurableAnchor {
    fn from(head: &ChainHead) -> Self {
        Self {
            version: ANCHOR_VERSION.to_string(),
            latest_sequence: head.latest_sequence,
            latest_digest: head.latest_digest.clone(),
            action_sequence: head.action_sequence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub exists: bool,
    pub identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentEvent {
    batch_id: BatchId,
    authorization_id: AuthorizationId,
    authorization_source: AuthorizationSource,
    plan_id: PlanId,
    plan_digest: DigestString,
    item_id: ItemId,
    action_id: ActionId,
    attempt_id: AttemptId,
    nonce: NonceId,
    requested_mode: RequestedMode,
    risk_tier: RiskTier,
    #[serde(with = "decimal_u64")]
    fence_epoch: u64,
    #[serde(with = "decimal_u64")]
    attempt_ordinal: u64,
    before_revalidation_digest: DigestString,
    source_path_hash: PathHash,
    policy_version: String,
    policy_digest: DigestString,
    protected_anchor_snapshot_digest: DigestString,
    adapter_capabilities_digest: DigestString,
    cleaner_set_digest: DigestString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeEvent {
    batch_id: BatchId,
    authorization_id: AuthorizationId,
    authorization_source: AuthorizationSource,
    plan_id: PlanId,
    plan_digest: DigestString,
    item_id: ItemId,
    action_id: ActionId,
    attempt_id: AttemptId,
    nonce: NonceId,
    requested_mode: RequestedMode,
    risk_tier: RiskTier,
    actual_platform_operation: String,
    policy_version: String,
    policy_digest: DigestString,
    adapter_version: String,
    started_at_unix_ms: String,
    finished_at_unix_ms: String,
    before_revalidation_digest: DigestString,
    source_path_hash: PathHash,
    #[serde(with = "decimal_u64")]
    intent_fence_epoch: u64,
    #[serde(with = "decimal_u64")]
    claim_fence_epoch: u64,
    stable_status: StableStatus,
    recovery_state: RecoveryState,
    source_postcheck: Observation,
    destination_postcheck: Option<Observation>,
    resulting_trash_locator: Option<String>,
    platform_result: Option<String>,
    platform_error_domain: Option<String>,
    platform_error_code: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    pub batch_id: BatchId,
    pub authorization_id: AuthorizationId,
    pub action_id: ActionId,
    pub attempt_id: AttemptId,
    pub disposition: RecoveryDisposition,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum EventPayload {
    AuthorizationRegistered {
        binding: AuthorizationBinding,
    },
    ExecutionClaimed {
        authorization_id: AuthorizationId,
        expected_plan_digest: DigestString,
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
    },
    RecoveryClaimed {
        authorization_id: AuthorizationId,
        expected_plan_digest: DigestString,
        #[serde(with = "decimal_u64")]
        previous_fence_epoch: u64,
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
    },
    ActionIntent(IntentEvent),
    ActionOutcome(OutcomeEvent),
    RecoveryOutcome(OutcomeEvent),
    RecoveryClassification {
        record: RecoveryRecord,
        #[serde(with = "decimal_u64")]
        claim_fence_epoch: u64,
    },
    ExecutionConsumed {
        authorization_id: AuthorizationId,
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    #[serde(with = "decimal_u64")]
    sequence: u64,
    recorded_at_unix_ms: String,
    monotonic_elapsed_ms: String,
    previous_digest: Option<String>,
    digest: String,
    payload: EventPayload,
}

#[derive(Debug, Clone)]
pub struct RegisterAuthorization {
    pub binding: AuthorizationBinding,
}

#[derive(Debug, Clone)]
pub struct IntentRequest {
    pub item_id: ItemId,
    pub action_id: ActionId,
    pub source_path_hash: PathHash,
    pub before_revalidation_digest: DigestString,
}

#[derive(Debug, Clone)]
pub struct SimulatedOutcome {
    actual_platform_operation: &'static str,
    adapter_version: String,
    started_at: SystemTime,
    finished_at: SystemTime,
    stable_status: StableStatus,
    recovery_state: RecoveryState,
    source_postcheck: Observation,
    destination_postcheck: Option<Observation>,
    resulting_trash_locator: Option<String>,
    platform_result: Option<String>,
    platform_error_domain: Option<String>,
    platform_error_code: Option<String>,
    notes: Vec<String>,
}

impl SimulatedOutcome {
    #[allow(clippy::too_many_arguments)]
    pub fn trash_success(
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_postcheck: Observation,
        destination_postcheck: Observation,
        resulting_trash_locator: Option<String>,
        platform_result: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        let destination_reported = destination_postcheck.exists
            || resulting_trash_locator
                .as_ref()
                .is_some_and(|value| !value.is_empty());
        let (stable_status, recovery_state) = if destination_reported {
            (
                StableStatus::TrashSucceededLocationReported,
                RecoveryState::TrashLocationReported,
            )
        } else {
            (
                StableStatus::TrashSucceededPlatformReported,
                RecoveryState::PlatformTrashReported,
            )
        };
        Self::validated(
            Self {
                actual_platform_operation: "simulated_trash",
                adapter_version: adapter_version.into(),
                started_at,
                finished_at,
                stable_status,
                recovery_state,
                source_postcheck,
                destination_postcheck: Some(destination_postcheck),
                resulting_trash_locator,
                platform_result: Some(platform_result.into()),
                platform_error_domain: None,
                platform_error_code: None,
                notes,
            },
            RequestedMode::Trash,
        )
    }

    pub fn permanent_success(
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_postcheck: Observation,
        platform_result: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::validated(
            Self {
                actual_platform_operation: "simulated_permanent_delete",
                adapter_version: adapter_version.into(),
                started_at,
                finished_at,
                stable_status: StableStatus::PermanentDeleteSucceeded,
                recovery_state: RecoveryState::InapplicablePermanent,
                source_postcheck,
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: Some(platform_result.into()),
                platform_error_domain: None,
                platform_error_code: None,
                notes,
            },
            RequestedMode::Permanent,
        )
    }

    pub fn failed_source_unchanged(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_identity: impl Into<String>,
        platform_result: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::validated(
            Self {
                actual_platform_operation: operation_for_mode(mode),
                adapter_version: adapter_version.into(),
                started_at,
                finished_at,
                stable_status: StableStatus::FailedSourceUnchanged,
                recovery_state: RecoveryState::FailedSourceUnchanged,
                source_postcheck: Observation {
                    exists: true,
                    identity: Some(source_identity.into()),
                },
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: Some(platform_result.into()),
                platform_error_domain: None,
                platform_error_code: None,
                notes,
            },
            mode,
        )
    }

    pub fn cancelled_before_action(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        at: SystemTime,
        source_identity: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::validated(
            Self {
                actual_platform_operation: operation_for_mode(mode),
                adapter_version: adapter_version.into(),
                started_at: at,
                finished_at: at,
                stable_status: StableStatus::CancelledBeforeAction,
                recovery_state: RecoveryState::CancelledBeforeAction,
                source_postcheck: Observation {
                    exists: true,
                    identity: Some(source_identity.into()),
                },
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: None,
                platform_error_domain: None,
                platform_error_code: None,
                notes,
            },
            mode,
        )
    }

    pub fn vanished_before_action(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        at: SystemTime,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::validated(
            Self {
                actual_platform_operation: operation_for_mode(mode),
                adapter_version: adapter_version.into(),
                started_at: at,
                finished_at: at,
                stable_status: StableStatus::VanishedBeforeAction,
                recovery_state: RecoveryState::VanishedBeforeAction,
                source_postcheck: Observation {
                    exists: false,
                    identity: None,
                },
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: None,
                platform_error_domain: None,
                platform_error_code: None,
                notes,
            },
            mode,
        )
    }

    pub fn indeterminate_after_crash(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_postcheck: Observation,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::validated(
            Self {
                actual_platform_operation: operation_for_mode(mode),
                adapter_version: adapter_version.into(),
                started_at,
                finished_at,
                stable_status: StableStatus::IndeterminateAfterCrash,
                recovery_state: RecoveryState::Indeterminate,
                source_postcheck,
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: None,
                platform_error_domain: None,
                platform_error_code: None,
                notes,
            },
            mode,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn platform_failure(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_postcheck: Observation,
        error_domain: impl Into<String>,
        error_code: impl Into<String>,
        platform_result: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        let recovery_state = if source_postcheck.exists
            && source_postcheck
                .identity
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        {
            RecoveryState::FailedSourceUnchanged
        } else {
            RecoveryState::Indeterminate
        };
        Self::validated(
            Self {
                actual_platform_operation: operation_for_mode(mode),
                adapter_version: adapter_version.into(),
                started_at,
                finished_at,
                stable_status: StableStatus::FailedPlatformError,
                recovery_state,
                source_postcheck,
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: Some(platform_result.into()),
                platform_error_domain: Some(error_domain.into()),
                platform_error_code: Some(error_code.into()),
                notes,
            },
            mode,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cancelled_by_platform(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_postcheck: Observation,
        error_domain: impl Into<String>,
        error_code: impl Into<String>,
        platform_result: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        let recovery_state = if source_postcheck.exists
            && source_postcheck
                .identity
                .as_ref()
                .is_some_and(|value| !value.is_empty())
        {
            RecoveryState::FailedSourceUnchanged
        } else {
            RecoveryState::Indeterminate
        };
        Self::validated(
            Self {
                actual_platform_operation: operation_for_mode(mode),
                adapter_version: adapter_version.into(),
                started_at,
                finished_at,
                stable_status: StableStatus::FailedCancelledByPlatform,
                recovery_state,
                source_postcheck,
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: Some(platform_result.into()),
                platform_error_domain: Some(error_domain.into()),
                platform_error_code: Some(error_code.into()),
                notes,
            },
            mode,
        )
    }

    pub fn indeterminate_platform_result(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_postcheck: Observation,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::validated(
            Self {
                actual_platform_operation: operation_for_mode(mode),
                adapter_version: adapter_version.into(),
                started_at,
                finished_at,
                stable_status: StableStatus::IndeterminatePlatformResult,
                recovery_state: RecoveryState::Indeterminate,
                source_postcheck,
                destination_postcheck: None,
                resulting_trash_locator: None,
                platform_result: None,
                platform_error_domain: None,
                platform_error_code: None,
                notes,
            },
            mode,
        )
    }

    fn validated(outcome: Self, mode: RequestedMode) -> Result<Self, AuditError> {
        validate_outcome_values(mode, &outcome)?;
        Ok(outcome)
    }
}

fn operation_for_mode(mode: RequestedMode) -> &'static str {
    match mode {
        RequestedMode::Trash => "simulated_trash",
        RequestedMode::Permanent => "simulated_permanent_delete",
    }
}

#[derive(Debug)]
pub struct RecoveryIntentView {
    info: IntentReservationInfo,
    authorization_source: AuthorizationSource,
}

impl RecoveryIntentView {
    pub fn attempt_id(&self) -> &AttemptId {
        self.info.attempt_id()
    }

    pub fn item_id(&self) -> &ItemId {
        self.info.item_id()
    }

    pub fn action_id(&self) -> &ActionId {
        self.info.action_id()
    }

    pub fn authorization_source(&self) -> AuthorizationSource {
        self.authorization_source
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryObservation {
    SourceStillPresent { source: Observation },
    SourceAbsentDestinationConfirmed { destination: Observation },
    SourceAbsentDestinationUnconfirmed,
    Unknown,
}

pub trait RecoveryObserver {
    fn observe(&self, intent: &RecoveryIntentView) -> Result<RecoveryObservation, AuditError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegritySummary {
    pub latest_sequence: u64,
    pub action_sequence: u64,
    pub latest_digest: Option<String>,
}

/// Simulation-only audit persistence.
///
/// The separate anchor detects accidental single-file rollback and interrupted anchor updates.
/// It is not a trusted anti-replay boundary: a same-UID attacker who can replace and rehash both
/// files can roll them back together. Callers must validate the full safety-sealed binding before
/// treating a claim as executable authority.
#[derive(Debug)]
pub struct AuditStore {
    root: PathBuf,
    state_dir: File,
    active_session: Arc<AtomicBool>,
    active_mutation_lock: Arc<Mutex<()>>,
    owner_pid: u32,
}

impl AuditStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, AuditError> {
        #[cfg(not(unix))]
        {
            let _ = root;
            return Err(AuditError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            let root = root.as_ref().to_path_buf();
            ensure_private_state_dir(&root)?;
            let state_dir = open_directory_nofollow(&root)?;
            let lock_exists = regular_file_exists_at(&state_dir, LOCK_FILE)?;
            let snapshot_exists = regular_file_exists_at(&state_dir, SNAPSHOT_FILE)?;
            let anchor_exists = regular_file_exists_at(&state_dir, ANCHOR_FILE)?;
            if !snapshot_exists && !anchor_exists {
                ensure_regular_file_at(&state_dir, LOCK_FILE, b"lock\n")?;
            } else if !lock_exists || !snapshot_exists && anchor_exists {
                return Err(AuditError::RollbackDetected);
            }
            let store = Self {
                root,
                state_dir,
                active_session: Arc::new(AtomicBool::new(false)),
                active_mutation_lock: Arc::new(Mutex::new(())),
                owner_pid: std::process::id(),
            };
            let _guard = store.lock()?;
            cleanup_stale_snapshot_temps(&store.state_dir, &store.root)?;
            if !snapshot_exists && !anchor_exists {
                ensure_regular_file_at(
                    &store.state_dir,
                    SNAPSHOT_FILE,
                    canonical_json(&SnapshotFile::default())?.as_bytes(),
                )?;
                ensure_regular_file_at(
                    &store.state_dir,
                    ANCHOR_FILE,
                    canonical_json(&DurableAnchor::default())?.as_bytes(),
                )?;
            } else if snapshot_exists && !anchor_exists {
                let snapshot: SnapshotFile =
                    read_json_file_at(&store.state_dir, SNAPSHOT_FILE, MAX_SNAPSHOT_BYTES)
                        .map_err(AuditError::StateDecode)?;
                verify_snapshot(&snapshot)?;
                if snapshot.head != ChainHead::default() {
                    return Err(AuditError::RollbackDetected);
                }
                ensure_regular_file_at(
                    &store.state_dir,
                    ANCHOR_FILE,
                    canonical_json(&DurableAnchor::default())?.as_bytes(),
                )?;
            }
            store.read_verified_snapshot()?;
            Ok(store)
        }
    }

    pub fn register_authorization(&self, request: RegisterAuthorization) -> Result<(), AuditError> {
        let _guard = self.lock()?;
        validate_binding(&request.binding)?;
        if request.binding.authorization_source != AuthorizationSource::DeterministicSimulation {
            return Err(AuditError::NonSimulationAuthorizationRejected);
        }
        let mut snapshot = self.read_verified_snapshot()?;
        if let Some(existing) = snapshot
            .projection
            .authorizations
            .get(&request.binding.authorization_id)
        {
            return if existing.binding == request.binding {
                Ok(())
            } else {
                Err(AuditError::AuthorizationAlreadyExists(
                    request.binding.authorization_id.as_str().to_string(),
                ))
            };
        }
        self.commit_event(
            &mut snapshot,
            EventPayload::AuthorizationRegistered {
                binding: request.binding,
            },
            false,
        )
    }

    pub fn claim_execution(
        &self,
        authorization_id: &AuthorizationId,
        expected_plan_digest: &DigestString,
    ) -> Result<ClaimedExecution, AuditError> {
        let guard = self.lock()?;
        let mut snapshot = self.read_verified_snapshot()?;
        let next_epoch = snapshot
            .projection
            .latest_fence_epoch
            .checked_add(1)
            .ok_or(AuditError::FenceEpochOverflow)?;
        let record = snapshot
            .projection
            .authorizations
            .get(authorization_id)
            .ok_or_else(|| {
                AuditError::AuthorizationUnknown(authorization_id.as_str().to_string())
            })?;
        if &record.binding.plan_digest != expected_plan_digest {
            return Err(AuditError::PlanDigestMismatch);
        }
        match record.state {
            AuthorizationState::Unused => {}
            AuthorizationState::Claimed { .. } => {
                return Err(AuditError::AuthorizationAlreadyClaimed(
                    authorization_id.as_str().to_string(),
                ));
            }
            AuthorizationState::Consumed { .. } => {
                return Err(AuditError::AuthorizationAlreadyConsumed(
                    authorization_id.as_str().to_string(),
                ));
            }
        }
        let binding = record.binding.clone();
        self.commit_event(
            &mut snapshot,
            EventPayload::ExecutionClaimed {
                authorization_id: authorization_id.clone(),
                expected_plan_digest: expected_plan_digest.clone(),
                fence_epoch: next_epoch,
            },
            false,
        )?;
        self.active_session.store(true, Ordering::Release);
        let claimed = ClaimedExecution {
            binding,
            fence_epoch: next_epoch,
            store_root: self.root.clone(),
            batch_lock: guard.into_file(),
            session_active: Arc::clone(&self.active_session),
            mutation_lock: Arc::clone(&self.active_mutation_lock),
            owner_pid: self.owner_pid,
        };
        Ok(claimed)
    }

    pub fn claim_recovery(
        &self,
        authorization_id: &AuthorizationId,
        expected_plan_digest: &DigestString,
    ) -> Result<ClaimedExecution, AuditError> {
        let guard = self.lock()?;
        let mut snapshot = self.read_verified_snapshot()?;
        let next_epoch = snapshot
            .projection
            .latest_fence_epoch
            .checked_add(1)
            .ok_or(AuditError::FenceEpochOverflow)?;
        let record = snapshot
            .projection
            .authorizations
            .get(authorization_id)
            .ok_or_else(|| {
                AuditError::AuthorizationUnknown(authorization_id.as_str().to_string())
            })?;
        if &record.binding.plan_digest != expected_plan_digest {
            return Err(AuditError::PlanDigestMismatch);
        }
        match record.state {
            AuthorizationState::Claimed { fence_epoch } => fence_epoch,
            AuthorizationState::Unused => {
                return Err(AuditError::AuthorizationNotClaimed(
                    authorization_id.as_str().to_string(),
                ));
            }
            AuthorizationState::Consumed { .. } => {
                return Err(AuditError::AuthorizationAlreadyConsumed(
                    authorization_id.as_str().to_string(),
                ));
            }
        };
        let previous_fence_epoch = match record.state {
            AuthorizationState::Claimed { fence_epoch } => fence_epoch,
            _ => unreachable!("state checked above"),
        };
        let binding = record.binding.clone();
        self.commit_event(
            &mut snapshot,
            EventPayload::RecoveryClaimed {
                authorization_id: authorization_id.clone(),
                expected_plan_digest: expected_plan_digest.clone(),
                previous_fence_epoch,
                fence_epoch: next_epoch,
            },
            false,
        )?;
        self.active_session.store(true, Ordering::Release);
        let claimed = ClaimedExecution {
            binding,
            fence_epoch: next_epoch,
            store_root: self.root.clone(),
            batch_lock: guard.into_file(),
            session_active: Arc::clone(&self.active_session),
            mutation_lock: Arc::clone(&self.active_mutation_lock),
            owner_pid: self.owner_pid,
        };
        Ok(claimed)
    }

    pub fn reserve_intent(
        &self,
        claimed: &ClaimedExecution,
        request: IntentRequest,
    ) -> Result<DurableIntentToken, AuditError> {
        self.reserve_intent_once(claimed, request)
            .and_then(IntentReservation::into_legacy_result)
    }

    pub fn reserve_intent_once(
        &self,
        claimed: &ClaimedExecution,
        request: IntentRequest,
    ) -> Result<IntentReservation, AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.ensure_claimed_store(claimed)?;
        let mut snapshot = self.read_verified_snapshot()?;
        let auth = snapshot
            .projection
            .authorizations
            .get(&claimed.binding.authorization_id)
            .cloned()
            .ok_or_else(|| {
                AuditError::AuthorizationUnknown(
                    claimed.binding.authorization_id.as_str().to_string(),
                )
            })?;
        match auth.state {
            AuthorizationState::Claimed { fence_epoch } if fence_epoch == claimed.fence_epoch => {}
            AuthorizationState::Claimed { .. } => return Err(AuditError::FenceEpochMismatch),
            AuthorizationState::Unused => {
                return Err(AuditError::AuthorizationNotClaimed(
                    claimed.binding.authorization_id.as_str().to_string(),
                ));
            }
            AuthorizationState::Consumed { .. } => {
                return Err(AuditError::AuthorizationAlreadyConsumed(
                    claimed.binding.authorization_id.as_str().to_string(),
                ));
            }
        }
        validate_intent_binding(&claimed.binding, &request)?;
        if let Some(intent) = snapshot.projection.intents.values().find(|intent| {
            intent.source_path_hash == request.source_path_hash
                && intent.authorization_id != claimed.binding.authorization_id
                && matches!(
                    intent.terminal_state,
                    IntentTerminalState::Reserved | IntentTerminalState::IndeterminateRecorded
                )
        }) {
            return Ok(IntentReservation::Conflicting(intent.reservation_info()));
        }
        if let Some(intent) = snapshot.projection.intents.values().find(|intent| {
            intent.authorization_id == claimed.binding.authorization_id
                && intent.action_id == request.action_id
        }) {
            return if intent.item_id == request.item_id
                && intent.source_path_hash == request.source_path_hash
                && intent.before_revalidation_digest == request.before_revalidation_digest
            {
                Ok(IntentReservation::Existing(intent.reservation_info()))
            } else {
                Ok(IntentReservation::Conflicting(intent.reservation_info()))
            };
        }

        let ordinal = snapshot
            .projection
            .next_attempt_ordinal
            .checked_add(1)
            .ok_or(AuditError::FenceEpochOverflow)?;
        let attempt_id = AttemptId::new(derive_digest_id(
            "attempt",
            &claimed.binding.authorization_id,
            claimed.fence_epoch,
            ordinal,
        ))?;
        let nonce = NonceId::new(derive_digest_id(
            "nonce",
            &claimed.binding.authorization_id,
            claimed.fence_epoch,
            ordinal,
        ))?;
        if snapshot.projection.intents.contains_key(&attempt_id) {
            return Err(AuditError::AttemptAlreadyExists(
                attempt_id.as_str().to_string(),
            ));
        }
        let risk_tier = *claimed
            .binding
            .risk_by_action
            .get(&request.action_id)
            .ok_or(AuditError::ActionNotAuthorized)?;
        let payload = EventPayload::ActionIntent(IntentEvent {
            batch_id: claimed.binding.batch_id.clone(),
            authorization_id: claimed.binding.authorization_id.clone(),
            authorization_source: claimed.binding.authorization_source,
            plan_id: claimed.binding.plan_id.clone(),
            plan_digest: claimed.binding.plan_digest.clone(),
            item_id: request.item_id,
            action_id: request.action_id,
            attempt_id: attempt_id.clone(),
            nonce,
            requested_mode: claimed.binding.requested_mode,
            risk_tier,
            fence_epoch: claimed.fence_epoch,
            attempt_ordinal: ordinal,
            before_revalidation_digest: request.before_revalidation_digest,
            source_path_hash: request.source_path_hash,
            policy_version: claimed.binding.policy_version.clone(),
            policy_digest: claimed.binding.policy_digest.clone(),
            protected_anchor_snapshot_digest: claimed
                .binding
                .protected_anchor_snapshot_digest
                .clone(),
            adapter_capabilities_digest: claimed.binding.adapter_capabilities_digest.clone(),
            cleaner_set_digest: claimed.binding.cleaner_set_digest.clone(),
        });
        self.commit_event(&mut snapshot, payload, true)?;
        Ok(IntentReservation::Created(
            snapshot
                .projection
                .intents
                .get(&attempt_id)
                .expect("reducer inserted intent")
                .as_token(),
        ))
    }

    pub fn record_outcome(
        &self,
        claimed: &ClaimedExecution,
        token: &DurableIntentToken,
        outcome: SimulatedOutcome,
    ) -> Result<(), AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.ensure_claimed_store(claimed)?;
        let mut snapshot = self.read_verified_snapshot()?;
        ensure_claim_matches_token(claimed, token)?;
        let auth = snapshot
            .projection
            .authorizations
            .get(&claimed.binding.authorization_id)
            .cloned()
            .ok_or_else(|| {
                AuditError::AuthorizationUnknown(
                    claimed.binding.authorization_id.as_str().to_string(),
                )
            })?;
        match auth.state {
            AuthorizationState::Claimed { fence_epoch } if fence_epoch == claimed.fence_epoch => {}
            AuthorizationState::Claimed { .. } => return Err(AuditError::FenceEpochMismatch),
            AuthorizationState::Unused => {
                return Err(AuditError::AuthorizationNotClaimed(
                    claimed.binding.authorization_id.as_str().to_string(),
                ));
            }
            AuthorizationState::Consumed { .. } => {
                return Err(AuditError::AuthorizationAlreadyConsumed(
                    claimed.binding.authorization_id.as_str().to_string(),
                ));
            }
        }
        let authority = snapshot
            .projection
            .intents
            .get(&token.attempt_id)
            .ok_or_else(|| AuditError::IntentNotFound(token.attempt_id.as_str().to_string()))?;
        validate_token_authority(token, authority)?;
        let payload = EventPayload::ActionOutcome(make_outcome_event(
            &claimed.binding,
            claimed.fence_epoch,
            authority,
            outcome,
        )?);
        if let EventPayload::ActionOutcome(proposed) = &payload
            && let Some(existing) = snapshot.projection.outcomes.get(&token.attempt_id)
        {
            return if existing == proposed {
                Ok(())
            } else {
                Err(AuditError::OutcomeAlreadyExists(
                    token.attempt_id.as_str().to_string(),
                ))
            };
        }
        self.commit_event(&mut snapshot, payload, false)
    }

    /// Records a reconciled terminal outcome without recreating the original intent capability.
    ///
    /// This is accepted only under a later recovery fence for an unresolved attempt belonging to
    /// the exact claimed authorization.
    pub fn record_recovery_outcome(
        &self,
        claimed: &ClaimedExecution,
        attempt_id: &AttemptId,
        outcome: SimulatedOutcome,
    ) -> Result<(), AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.ensure_claimed_store(claimed)?;
        let mut snapshot = self.read_verified_snapshot()?;
        validate_current_claim(
            &snapshot.projection,
            &claimed.binding.authorization_id,
            claimed.fence_epoch,
        )?;
        let authority = snapshot
            .projection
            .intents
            .get(attempt_id)
            .ok_or_else(|| AuditError::IntentNotFound(attempt_id.as_str().to_string()))?;
        if authority.authorization_id != claimed.binding.authorization_id
            || authority.batch_id != claimed.binding.batch_id
            || claimed.binding.item_by_action.get(&authority.action_id) != Some(&authority.item_id)
            || claimed.fence_epoch <= authority.fence_epoch
        {
            return Err(AuditError::RecoveryClaimRequired);
        }
        let payload = EventPayload::RecoveryOutcome(make_outcome_event(
            &claimed.binding,
            claimed.fence_epoch,
            authority,
            outcome,
        )?);
        if let EventPayload::RecoveryOutcome(proposed) = &payload
            && let Some(existing) = snapshot.projection.outcomes.get(attempt_id)
        {
            if existing == proposed {
                return Ok(());
            }
            if !outcome_is_indeterminate(existing) {
                return Err(AuditError::OutcomeAlreadyExists(
                    attempt_id.as_str().to_string(),
                ));
            }
        }
        self.commit_event(&mut snapshot, payload, false)
    }

    pub fn unresolved_recovery_intents(
        &self,
        claimed: &ClaimedExecution,
    ) -> Result<Vec<IntentReservationInfo>, AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.ensure_claimed_store(claimed)?;
        let snapshot = self.read_verified_snapshot()?;
        validate_current_claim(
            &snapshot.projection,
            &claimed.binding.authorization_id,
            claimed.fence_epoch,
        )?;
        Ok(snapshot
            .projection
            .intents
            .values()
            .filter(|intent| {
                intent.authorization_id == claimed.binding.authorization_id
                    && intent.terminal_state != IntentTerminalState::OutcomeRecorded
            })
            .map(IntentAuthority::reservation_info)
            .collect())
    }

    pub fn classify_recovery(
        &self,
        claimed: &ClaimedExecution,
        observer: &dyn RecoveryObserver,
    ) -> Result<Vec<RecoveryRecord>, AuditError> {
        let attempt_ids: Vec<AttemptId> = {
            let _mutation_guard = claimed.lock_mutation()?;
            self.ensure_claimed_store(claimed)?;
            let snapshot = self.read_verified_snapshot()?;
            validate_current_claim(
                &snapshot.projection,
                &claimed.binding.authorization_id,
                claimed.fence_epoch,
            )?;
            snapshot
                .projection
                .intents
                .values()
                .filter(|intent| intent.authorization_id == claimed.binding.authorization_id)
                .map(|intent| intent.attempt_id.clone())
                .collect()
        };
        let mut appended = Vec::new();
        for attempt_id in attempt_ids {
            let view = {
                let _mutation_guard = claimed.lock_mutation()?;
                self.ensure_claimed_store(claimed)?;
                let snapshot = self.read_verified_snapshot()?;
                validate_current_claim(
                    &snapshot.projection,
                    &claimed.binding.authorization_id,
                    claimed.fence_epoch,
                )?;
                let authority = snapshot
                    .projection
                    .intents
                    .get(&attempt_id)
                    .ok_or_else(|| AuditError::IntentNotFound(attempt_id.as_str().to_string()))?;
                if authority.terminal_state == IntentTerminalState::OutcomeRecorded {
                    continue;
                }
                RecoveryIntentView {
                    info: authority.reservation_info(),
                    authorization_source: claimed.binding.authorization_source,
                }
            };
            let observation = observer.observe(&view)?;
            let (disposition, reason) =
                classify_observation(claimed.requested_mode(), observation)?;
            let _mutation_guard = claimed.lock_mutation()?;
            self.ensure_claimed_store(claimed)?;
            let mut snapshot = self.read_verified_snapshot()?;
            let authority = snapshot
                .projection
                .intents
                .get(&attempt_id)
                .ok_or_else(|| AuditError::IntentNotFound(attempt_id.as_str().to_string()))?;
            validate_current_claim(
                &snapshot.projection,
                &claimed.binding.authorization_id,
                claimed.fence_epoch,
            )?;
            if authority.terminal_state == IntentTerminalState::OutcomeRecorded {
                continue;
            }
            let record = RecoveryRecord {
                batch_id: authority.batch_id.clone(),
                authorization_id: authority.authorization_id.clone(),
                action_id: authority.action_id.clone(),
                attempt_id: authority.attempt_id.clone(),
                disposition,
                reason,
            };
            if snapshot.projection.recoveries.get(&attempt_id) != Some(&record) {
                self.commit_event(
                    &mut snapshot,
                    EventPayload::RecoveryClassification {
                        record: record.clone(),
                        claim_fence_epoch: claimed.fence_epoch,
                    },
                    true,
                )?;
            }
            appended.push(record);
        }
        Ok(appended)
    }

    pub fn consume_execution(&self, claimed: &ClaimedExecution) -> Result<(), AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.ensure_claimed_store(claimed)?;
        let mut snapshot = self.read_verified_snapshot()?;
        let record = snapshot
            .projection
            .authorizations
            .get(&claimed.binding.authorization_id)
            .ok_or_else(|| {
                AuditError::AuthorizationUnknown(
                    claimed.binding.authorization_id.as_str().to_string(),
                )
            })?;
        match record.state {
            AuthorizationState::Claimed { fence_epoch } if fence_epoch == claimed.fence_epoch => {}
            AuthorizationState::Claimed { .. } => return Err(AuditError::FenceEpochMismatch),
            AuthorizationState::Unused => {
                return Err(AuditError::AuthorizationNotClaimed(
                    claimed.binding.authorization_id.as_str().to_string(),
                ));
            }
            AuthorizationState::Consumed { fence_epoch } => {
                return if fence_epoch == claimed.fence_epoch {
                    Ok(())
                } else {
                    Err(AuditError::AuthorizationAlreadyConsumed(
                        claimed.binding.authorization_id.as_str().to_string(),
                    ))
                };
            }
        }
        let unresolved = snapshot.projection.intents.values().any(|intent| {
            intent.authorization_id == claimed.binding.authorization_id
                && intent.terminal_state != IntentTerminalState::OutcomeRecorded
        });
        if unresolved {
            return Err(AuditError::UnresolvedIntentsRemain);
        }
        self.commit_event(
            &mut snapshot,
            EventPayload::ExecutionConsumed {
                authorization_id: claimed.binding.authorization_id.clone(),
                fence_epoch: claimed.fence_epoch,
            },
            false,
        )
    }

    pub fn verify_integrity(&self) -> Result<IntegritySummary, AuditError> {
        self.ensure_process()?;
        if self.active_session.load(Ordering::Acquire) {
            let session_guard = self
                .active_mutation_lock
                .lock()
                .map_err(|_| AuditError::SessionLockPoisoned)?;
            if self.active_session.load(Ordering::Acquire) {
                return self.integrity_summary();
            }
            drop(session_guard);
        }
        let _store_guard = self.lock()?;
        self.integrity_summary()
    }

    fn integrity_summary(&self) -> Result<IntegritySummary, AuditError> {
        let snapshot = self.read_verified_snapshot()?;
        Ok(IntegritySummary {
            latest_sequence: snapshot.head.latest_sequence,
            action_sequence: snapshot.head.action_sequence,
            latest_digest: snapshot.head.latest_digest,
        })
    }

    fn ensure_claimed_store(&self, claimed: &ClaimedExecution) -> Result<(), AuditError> {
        self.ensure_process()?;
        claimed.validate_current_process()?;
        if !claimed.validates_store(&self.root) {
            return Err(AuditError::AuthorizationBindingMismatch);
        }
        if !claimed.session_active.load(Ordering::Acquire) {
            return Err(AuditError::FenceEpochMismatch);
        }
        validate_directory_descriptor(&self.state_dir, &self.root)?;
        validate_lock_descriptor(&claimed.batch_lock, &self.state_dir)?;
        Ok(())
    }

    fn read_verified_snapshot(&self) -> Result<SnapshotFile, AuditError> {
        validate_directory_descriptor(&self.state_dir, &self.root)?;
        let snapshot = read_json_file_at(&self.state_dir, SNAPSHOT_FILE, MAX_SNAPSHOT_BYTES)
            .map_err(AuditError::StateDecode)?;
        verify_snapshot(&snapshot)?;
        let anchor: DurableAnchor =
            read_json_file_at(&self.state_dir, ANCHOR_FILE, MAX_ANCHOR_BYTES)
                .map_err(AuditError::AnchorDecode)?;
        verify_anchor(&anchor)?;
        match compare_anchor(&snapshot, &anchor)? {
            AnchorComparison::Current => {}
            AnchorComparison::SnapshotOneAhead => {
                self.write_anchor(&DurableAnchor::from(&snapshot.head))?;
            }
        }
        Ok(snapshot)
    }

    fn write_anchor(&self, anchor: &DurableAnchor) -> Result<(), AuditError> {
        let bytes = canonical_json(anchor)?;
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(AuditError::StateTooLarge);
        }
        atomic_replace_named_at(&self.state_dir, ANCHOR_FILE, bytes.as_bytes())
    }

    fn commit_event(
        &self,
        snapshot: &mut SnapshotFile,
        payload: EventPayload,
        reserve_outcome_capacity: bool,
    ) -> Result<(), AuditError> {
        verify_snapshot(snapshot)?;
        let sequence = snapshot
            .head
            .latest_sequence
            .checked_add(1)
            .ok_or(AuditError::FenceEpochOverflow)?;
        let previous_digest = snapshot.head.latest_digest.clone();
        let recorded_at = unix_ms_string(SystemTime::now())?;
        let monotonic = monotonic_elapsed_ms_string();
        let payload_json = canonical_json(&payload)?;
        let digest = digest_record(
            sequence,
            &recorded_at,
            &monotonic,
            previous_digest.as_deref(),
            &payload_json,
        );
        let record = JournalRecord {
            sequence,
            recorded_at_unix_ms: recorded_at,
            monotonic_elapsed_ms: monotonic,
            previous_digest,
            digest: digest.clone(),
            payload: payload.clone(),
        };
        let mut candidate_projection = snapshot.projection.clone();
        apply_payload(&mut candidate_projection, &record.payload)?;
        let required_future_events =
            required_future_event_slots(&candidate_projection, &record.payload)?;
        let candidate_event_count = snapshot
            .events
            .len()
            .checked_add(1)
            .ok_or(AuditError::StateTooLarge)?;
        if candidate_event_count > MAX_EVENTS
            || candidate_event_count
                .checked_add(required_future_events)
                .is_none_or(|count| count > MAX_EVENTS)
        {
            return Err(AuditError::StateTooLarge);
        }
        if canonical_json(&record)?.len() > MAX_EVENT_BYTES {
            return Err(AuditError::RecordTooLarge);
        }
        snapshot.projection = candidate_projection;
        if matches!(
            record.payload,
            EventPayload::ActionIntent(_)
                | EventPayload::ActionOutcome(_)
                | EventPayload::RecoveryOutcome(_)
        ) {
            snapshot.head.action_sequence = snapshot
                .head
                .action_sequence
                .checked_add(1)
                .ok_or(AuditError::FenceEpochOverflow)?;
        }
        snapshot.events.push(record);
        snapshot.head.latest_sequence = sequence;
        snapshot.head.latest_digest = Some(digest);
        verify_snapshot(snapshot)?;
        let bytes = canonical_json(snapshot)?;
        let reserved_bytes = required_future_events
            .checked_mul(MAX_EVENT_COMMIT_GROWTH)
            .ok_or(AuditError::StateTooLarge)?;
        if bytes.len() > MAX_SNAPSHOT_BYTES
            || (reserve_outcome_capacity || required_future_events != 0)
                && bytes
                    .len()
                    .checked_add(reserved_bytes)
                    .is_none_or(|size| size > MAX_SNAPSHOT_BYTES)
        {
            return Err(AuditError::StateTooLarge);
        }
        validate_directory_descriptor(&self.state_dir, &self.root)?;
        atomic_replace_named_at(&self.state_dir, SNAPSHOT_FILE, bytes.as_bytes())?;
        self.write_anchor(&DurableAnchor::from(&snapshot.head))
    }

    fn lock(&self) -> Result<StoreLock, AuditError> {
        self.ensure_process()?;
        validate_directory_descriptor(&self.state_dir, &self.root)?;
        let file = openat_file(&self.state_dir, LOCK_FILE, true)?;
        validate_lock_descriptor(&file, &self.state_dir)?;
        file.try_lock_exclusive()
            .map_err(|_| AuditError::ConcurrentWriterDenied)?;
        Ok(StoreLock { _file: file })
    }

    fn ensure_process(&self) -> Result<(), AuditError> {
        if self.owner_pid != std::process::id() {
            return Err(AuditError::ForkedProcess);
        }
        Ok(())
    }
}

fn required_future_event_slots(
    projection: &Projection,
    committed_payload: &EventPayload,
) -> Result<usize, AuditError> {
    if matches!(committed_payload, EventPayload::ExecutionConsumed { .. }) {
        return Ok(0);
    }
    let has_claimed_authorization = projection
        .authorizations
        .values()
        .any(|record| matches!(record.state, AuthorizationState::Claimed { .. }));
    if !has_claimed_authorization {
        return Ok(0);
    }
    let reserved = projection
        .intents
        .values()
        .filter(|intent| intent.terminal_state == IntentTerminalState::Reserved)
        .count();
    let indeterminate = projection
        .intents
        .values()
        .filter(|intent| intent.terminal_state == IntentTerminalState::IndeterminateRecorded)
        .count();
    // A reserved intent may first produce an indeterminate outcome and then require a recovery
    // outcome. An already-indeterminate intent still needs one recovery outcome. Preserve one
    // eventual consume event as well. Before recovery starts, preserve one recovery-claim event;
    // recovery events spend that reserved claim slot instead of recursively reserving unbounded
    // crash cycles. Every non-consume commit is checked so unrelated events cannot steal slots.
    let terminal_outcomes = reserved
        .checked_mul(2)
        .and_then(|count| count.checked_add(indeterminate))
        .ok_or(AuditError::StateTooLarge)?;
    let recovery_claim = usize::from(!matches!(
        committed_payload,
        EventPayload::RecoveryClaimed { .. }
            | EventPayload::RecoveryOutcome(_)
            | EventPayload::RecoveryClassification { .. }
    ));
    terminal_outcomes
        .checked_add(1)
        .and_then(|count| count.checked_add(recovery_claim))
        .ok_or(AuditError::StateTooLarge)
}

#[derive(Debug)]
struct StoreLock {
    _file: File,
}

impl StoreLock {
    fn into_file(self) -> File {
        self._file
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit store is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("claimed execution mutation lock is poisoned")]
    SessionLockPoisoned,
    #[error("audit handles cannot be reused after process fork")]
    ForkedProcess,
    #[error("state directory must be absolute")]
    StateDirNotAbsolute,
    #[error("state directory {0} contains unsafe components")]
    UnsafeStateDir(String),
    #[error("state directory or file {0} must not be a symlink")]
    SymlinkRejected(String),
    #[error("state directory {0} is not private enough")]
    StateDirNotPrivate(String),
    #[error("stable identifier field {field} is invalid")]
    InvalidStableId { field: &'static str },
    #[error("authorization {0} already exists")]
    AuthorizationAlreadyExists(String),
    #[error("authorization {0} is unknown")]
    AuthorizationUnknown(String),
    #[error("authorization {0} must be claimed before use")]
    AuthorizationNotClaimed(String),
    #[error("authorization {0} is already claimed")]
    AuthorizationAlreadyClaimed(String),
    #[error("authorization {0} is already consumed")]
    AuthorizationAlreadyConsumed(String),
    #[error("authorization plan digest mismatch")]
    PlanDigestMismatch,
    #[error("authorization binding mismatch")]
    AuthorizationBindingMismatch,
    #[error("raw audit registration accepts deterministic simulation authority only")]
    NonSimulationAuthorizationRejected,
    #[error("action is not authorized")]
    ActionNotAuthorized,
    #[error("fence epoch mismatch")]
    FenceEpochMismatch,
    #[error("a later recovery claim is required for tokenless outcome recording")]
    RecoveryClaimRequired,
    #[error("fence epoch overflow")]
    FenceEpochOverflow,
    #[error("attempt {0} already exists")]
    AttemptAlreadyExists(String),
    #[error("action {0} already has a reserved or completed attempt")]
    ActionAlreadyReserved(String),
    #[error("attempt {0} has no durable matching intent")]
    IntentNotFound(String),
    #[error("outcome already exists for attempt {0}")]
    OutcomeAlreadyExists(String),
    #[error("unresolved intents remain")]
    UnresolvedIntentsRemain,
    #[error("tail truncation or durable head mismatch detected")]
    HeadMismatch,
    #[error("snapshot rollback or divergence from durable anchor detected")]
    RollbackDetected,
    #[error("journal tampering detected at sequence {sequence}: {reason}")]
    JournalTampered { sequence: u64, reason: String },
    #[error("state file is too large")]
    StateTooLarge,
    #[error("journal file is too large")]
    JournalTooLarge,
    #[error("record exceeds bounded maximum size")]
    RecordTooLarge,
    #[error("outcome fields, timestamps, or status tuple are invalid")]
    InvalidOutcome,
    #[error("recovery observation contradicts its evidence")]
    InvalidObservation,
    #[error("successful outcome requires source absence")]
    SuccessRequiresSourceAbsent,
    #[error("trash success requires confirmed destination or trash locator evidence")]
    TrashSuccessRequiresDestinationEvidence,
    #[error("permanent success must not claim destination or trash locator")]
    PermanentSuccessMustNotClaimDestination,
    #[error("state file decode failed: {0}")]
    StateDecode(std::io::Error),
    #[error("head file decode failed: {0}")]
    HeadDecode(std::io::Error),
    #[error("anchor file decode failed: {0}")]
    AnchorDecode(std::io::Error),
    #[error("journal decode failed: {0}")]
    JournalDecode(serde_json::Error),
    #[error("invalid clock value")]
    InvalidClock,
    #[error("concurrent writer denied by exclusive store lock")]
    ConcurrentWriterDenied,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn validate_binding(binding: &AuthorizationBinding) -> Result<(), AuditError> {
    let represented_items: BTreeSet<_> = binding.item_by_action.values().cloned().collect();
    if binding.authorization_source != AuthorizationSource::DeterministicSimulation {
        return Err(AuditError::NonSimulationAuthorizationRejected);
    }
    if binding.action_count != binding.action_ids.len() as u64
        || binding.action_ids.is_empty()
        || binding.item_ids.is_empty()
        || binding.action_ids.len() > MAX_BINDING_ACTIONS
        || binding.item_ids.len() > MAX_BINDING_ITEMS
        || binding.policy_version.is_empty()
        || binding.policy_version.len() > MAX_POLICY_VERSION_BYTES
        || binding.risk_by_action.len() != binding.action_ids.len()
        || binding.item_by_action.len() != binding.action_ids.len()
        || represented_items != binding.item_ids
        || binding
            .action_ids
            .iter()
            .any(|action_id| !binding.risk_by_action.contains_key(action_id))
        || binding.item_by_action.iter().any(|(action_id, item_id)| {
            !binding.action_ids.contains(action_id) || !binding.item_ids.contains(item_id)
        })
        || binding.requested_mode == RequestedMode::Permanent
            && binding
                .risk_by_action
                .values()
                .any(|risk| *risk != RiskTier::R4)
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_intent_binding(
    binding: &AuthorizationBinding,
    request: &IntentRequest,
) -> Result<(), AuditError> {
    if binding.item_by_action.get(&request.action_id) != Some(&request.item_id) {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_intent_event(
    binding: &AuthorizationBinding,
    event: &IntentEvent,
) -> Result<(), AuditError> {
    if event.authorization_id != binding.authorization_id
        || event.authorization_source != binding.authorization_source
        || event.batch_id != binding.batch_id
        || event.plan_id != binding.plan_id
        || event.plan_digest != binding.plan_digest
        || event.requested_mode != binding.requested_mode
        || binding.item_by_action.get(&event.action_id) != Some(&event.item_id)
        || binding.risk_by_action.get(&event.action_id) != Some(&event.risk_tier)
        || event.policy_version != binding.policy_version
        || event.policy_digest != binding.policy_digest
        || event.protected_anchor_snapshot_digest != binding.protected_anchor_snapshot_digest
        || event.adapter_capabilities_digest != binding.adapter_capabilities_digest
        || event.cleaner_set_digest != binding.cleaner_set_digest
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn ensure_claim_matches_token(
    claimed: &ClaimedExecution,
    token: &DurableIntentToken,
) -> Result<(), AuditError> {
    token.validate_current_process()?;
    if token.authorization_id != claimed.binding.authorization_id
        || token.batch_id != claimed.binding.batch_id
        || token.plan_id != claimed.binding.plan_id
        || token.plan_digest != claimed.binding.plan_digest
        || token.requested_mode != claimed.binding.requested_mode
        || token.fence_epoch != claimed.fence_epoch
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_token_authority(
    token: &DurableIntentToken,
    authority: &IntentAuthority,
) -> Result<(), AuditError> {
    if token.attempt_id != authority.attempt_id
        || token.nonce != authority.nonce
        || token.authorization_id != authority.authorization_id
        || token.batch_id != authority.batch_id
        || token.plan_id != authority.plan_id
        || token.plan_digest != authority.plan_digest
        || token.item_id != authority.item_id
        || token.action_id != authority.action_id
        || token.requested_mode != authority.requested_mode
        || token.risk_tier != authority.risk_tier
        || token.source_path_hash != authority.source_path_hash
        || token.before_revalidation_digest != authority.before_revalidation_digest
        || token.fence_epoch != authority.fence_epoch
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_outcome(
    token: &DurableIntentToken,
    outcome: &SimulatedOutcome,
) -> Result<(), AuditError> {
    let started_at = unix_ms_string(outcome.started_at)?;
    let finished_at = unix_ms_string(outcome.finished_at)?;
    if parse_decimal_u64(&started_at)? > parse_decimal_u64(&finished_at)?
        || outcome.actual_platform_operation.is_empty()
        || outcome.actual_platform_operation.len() > MAX_TEXT_BYTES
        || outcome.actual_platform_operation != operation_for_mode(token.requested_mode)
        || outcome.adapter_version.is_empty()
        || outcome.adapter_version.len() > MAX_TEXT_BYTES
        || outcome
            .source_postcheck
            .identity
            .as_ref()
            .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
        || outcome
            .destination_postcheck
            .as_ref()
            .and_then(|observation| observation.identity.as_ref())
            .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
        || [
            outcome.resulting_trash_locator.as_ref(),
            outcome.platform_result.as_ref(),
            outcome.platform_error_domain.as_ref(),
            outcome.platform_error_code.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.len() > MAX_TEXT_BYTES)
        || outcome
            .platform_result
            .as_ref()
            .is_some_and(String::is_empty)
        || outcome
            .platform_error_domain
            .as_ref()
            .is_some_and(String::is_empty)
        || outcome
            .platform_error_code
            .as_ref()
            .is_some_and(String::is_empty)
    {
        return Err(AuditError::InvalidOutcome);
    }
    validate_outcome_tuple(
        token.requested_mode,
        outcome.stable_status,
        outcome.recovery_state,
        &outcome.source_postcheck,
        outcome.destination_postcheck.as_ref(),
        outcome.resulting_trash_locator.as_ref(),
        outcome.platform_result.as_ref(),
        outcome.platform_error_domain.as_ref(),
        outcome.platform_error_code.as_ref(),
    )
}

fn make_outcome_event(
    binding: &AuthorizationBinding,
    claim_fence_epoch: u64,
    authority: &IntentAuthority,
    outcome: SimulatedOutcome,
) -> Result<OutcomeEvent, AuditError> {
    validate_outcome_values(authority.requested_mode, &outcome)?;
    Ok(OutcomeEvent {
        batch_id: authority.batch_id.clone(),
        authorization_id: authority.authorization_id.clone(),
        authorization_source: binding.authorization_source,
        plan_id: authority.plan_id.clone(),
        plan_digest: authority.plan_digest.clone(),
        item_id: authority.item_id.clone(),
        action_id: authority.action_id.clone(),
        attempt_id: authority.attempt_id.clone(),
        nonce: authority.nonce.clone(),
        requested_mode: authority.requested_mode,
        risk_tier: authority.risk_tier,
        actual_platform_operation: outcome.actual_platform_operation.to_string(),
        policy_version: binding.policy_version.clone(),
        policy_digest: binding.policy_digest.clone(),
        adapter_version: outcome.adapter_version,
        started_at_unix_ms: unix_ms_string(outcome.started_at)?,
        finished_at_unix_ms: unix_ms_string(outcome.finished_at)?,
        before_revalidation_digest: authority.before_revalidation_digest.clone(),
        source_path_hash: authority.source_path_hash.clone(),
        intent_fence_epoch: authority.fence_epoch,
        claim_fence_epoch,
        stable_status: outcome.stable_status,
        recovery_state: outcome.recovery_state,
        source_postcheck: outcome.source_postcheck,
        destination_postcheck: outcome.destination_postcheck,
        resulting_trash_locator: outcome.resulting_trash_locator,
        platform_result: outcome.platform_result,
        platform_error_domain: outcome.platform_error_domain,
        platform_error_code: outcome.platform_error_code,
        notes: bounded_notes(outcome.notes)?,
    })
}

fn validate_outcome_values(
    requested_mode: RequestedMode,
    outcome: &SimulatedOutcome,
) -> Result<(), AuditError> {
    let token = DurableIntentToken {
        attempt_id: AttemptId::new("validation-attempt")?,
        nonce: NonceId::new("validation-nonce")?,
        authorization_id: AuthorizationId::new("validation-authorization")?,
        batch_id: BatchId::new("validation-batch")?,
        plan_id: PlanId::new("validation-plan")?,
        plan_digest: DigestString::new("validation-plan-digest")?,
        item_id: ItemId::new("validation-item")?,
        action_id: ActionId::new("validation-action")?,
        requested_mode,
        risk_tier: RiskTier::R4,
        source_path_hash: PathHash::new("validation-path")?,
        before_revalidation_digest: DigestString::new("validation-revalidation")?,
        fence_epoch: 1,
        creator_pid: std::process::id(),
    };
    validate_outcome(&token, outcome)
}

fn validate_outcome_event(event: &OutcomeEvent) -> Result<(), AuditError> {
    let started = parse_decimal_u64(&event.started_at_unix_ms)?;
    let finished = parse_decimal_u64(&event.finished_at_unix_ms)?;
    if started > finished
        || event.actual_platform_operation.is_empty()
        || event.actual_platform_operation.len() > MAX_TEXT_BYTES
        || event.actual_platform_operation != operation_for_mode(event.requested_mode)
        || event.adapter_version.is_empty()
        || event.adapter_version.len() > MAX_TEXT_BYTES
        || event.notes.len() > MAX_NOTES
        || event.notes.iter().any(|note| note.len() > MAX_NOTE_BYTES)
        || event
            .source_postcheck
            .identity
            .as_ref()
            .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
        || event
            .destination_postcheck
            .as_ref()
            .and_then(|observation| observation.identity.as_ref())
            .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
        || [
            event.resulting_trash_locator.as_ref(),
            event.platform_result.as_ref(),
            event.platform_error_domain.as_ref(),
            event.platform_error_code.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.len() > MAX_TEXT_BYTES)
        || event.platform_result.as_ref().is_some_and(String::is_empty)
        || event
            .platform_error_domain
            .as_ref()
            .is_some_and(String::is_empty)
        || event
            .platform_error_code
            .as_ref()
            .is_some_and(String::is_empty)
    {
        return Err(AuditError::InvalidOutcome);
    }
    validate_outcome_tuple(
        event.requested_mode,
        event.stable_status,
        event.recovery_state,
        &event.source_postcheck,
        event.destination_postcheck.as_ref(),
        event.resulting_trash_locator.as_ref(),
        event.platform_result.as_ref(),
        event.platform_error_domain.as_ref(),
        event.platform_error_code.as_ref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_outcome_tuple(
    requested_mode: RequestedMode,
    stable_status: StableStatus,
    recovery_state: RecoveryState,
    source_postcheck: &Observation,
    destination_postcheck: Option<&Observation>,
    resulting_trash_locator: Option<&String>,
    platform_result: Option<&String>,
    platform_error_domain: Option<&String>,
    platform_error_code: Option<&String>,
) -> Result<(), AuditError> {
    if !observation_is_consistent(source_postcheck)
        || destination_postcheck.is_some_and(|value| !observation_is_consistent(value))
    {
        return Err(AuditError::InvalidOutcome);
    }
    let destination_exists = destination_postcheck.is_some_and(|value| value.exists);
    let has_locator = resulting_trash_locator.is_some_and(|value| !value.is_empty());
    match (stable_status, recovery_state) {
        (StableStatus::TrashSucceededPlatformReported, RecoveryState::PlatformTrashReported)
            if requested_mode == RequestedMode::Trash
                && !source_postcheck.exists
                && !destination_exists
                && !has_locator
                && platform_result.is_some()
                && platform_error_domain.is_none()
                && platform_error_code.is_none() =>
        {
            Ok(())
        }
        (StableStatus::TrashSucceededLocationReported, RecoveryState::TrashLocationReported)
            if requested_mode == RequestedMode::Trash
                && !source_postcheck.exists
                && (destination_exists || has_locator)
                && platform_result.is_some()
                && platform_error_domain.is_none()
                && platform_error_code.is_none() =>
        {
            Ok(())
        }
        (StableStatus::PermanentDeleteSucceeded, RecoveryState::InapplicablePermanent)
            if requested_mode == RequestedMode::Permanent
                && !source_postcheck.exists
                && destination_postcheck.is_none()
                && !has_locator
                && platform_result.is_some()
                && platform_error_domain.is_none()
                && platform_error_code.is_none() =>
        {
            Ok(())
        }
        (StableStatus::FailedSourceUnchanged, RecoveryState::FailedSourceUnchanged)
            if source_postcheck.exists
                && source_postcheck
                    .identity
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                && destination_postcheck.is_none()
                && !has_locator
                && platform_result.is_some()
                && platform_error_domain.is_none()
                && platform_error_code.is_none() =>
        {
            Ok(())
        }
        (StableStatus::VanishedBeforeAction, RecoveryState::VanishedBeforeAction)
            if !source_postcheck.exists
                && source_postcheck.identity.is_none()
                && destination_postcheck.is_none()
                && !has_locator
                && platform_result.is_none()
                && platform_error_domain.is_none()
                && platform_error_code.is_none() =>
        {
            Ok(())
        }
        (StableStatus::CancelledBeforeAction, RecoveryState::CancelledBeforeAction)
            if source_postcheck.exists
                && source_postcheck
                    .identity
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                && destination_postcheck.is_none()
                && !has_locator
                && platform_result.is_none()
                && platform_error_domain.is_none()
                && platform_error_code.is_none() =>
        {
            Ok(())
        }
        (StableStatus::FailedPlatformError, RecoveryState::FailedSourceUnchanged)
        | (StableStatus::FailedCancelledByPlatform, RecoveryState::FailedSourceUnchanged)
        | (StableStatus::FailedPlatformError, RecoveryState::Indeterminate)
        | (StableStatus::FailedCancelledByPlatform, RecoveryState::Indeterminate)
            if destination_postcheck.is_none()
                && !has_locator
                && platform_result.is_some()
                && platform_error_domain.is_some()
                && platform_error_code.is_some()
                && (recovery_state == RecoveryState::Indeterminate
                    || source_postcheck.exists
                        && source_postcheck
                            .identity
                            .as_ref()
                            .is_some_and(|value| !value.is_empty())) =>
        {
            Ok(())
        }
        (StableStatus::IndeterminateAfterCrash, RecoveryState::Indeterminate)
        | (StableStatus::IndeterminatePlatformResult, RecoveryState::Indeterminate)
            if destination_postcheck.is_none()
                && !has_locator
                && platform_result.is_none()
                && platform_error_domain.is_none()
                && platform_error_code.is_none() =>
        {
            Ok(())
        }
        _ => Err(AuditError::InvalidOutcome),
    }
}

fn observation_is_consistent(observation: &Observation) -> bool {
    if observation.exists {
        observation
            .identity
            .as_ref()
            .is_some_and(|value| !value.is_empty())
    } else {
        observation.identity.is_none()
    }
}

fn outcome_matches_authority(event: &OutcomeEvent, authority: &IntentAuthority) -> bool {
    event.authorization_id == authority.authorization_id
        && event.batch_id == authority.batch_id
        && event.plan_id == authority.plan_id
        && event.plan_digest == authority.plan_digest
        && event.item_id == authority.item_id
        && event.action_id == authority.action_id
        && event.nonce == authority.nonce
        && event.requested_mode == authority.requested_mode
        && event.risk_tier == authority.risk_tier
        && event.source_path_hash == authority.source_path_hash
        && event.before_revalidation_digest == authority.before_revalidation_digest
        && event.intent_fence_epoch == authority.fence_epoch
}

fn classify_observation(
    mode: RequestedMode,
    observation: RecoveryObservation,
) -> Result<(RecoveryDisposition, String), AuditError> {
    match observation {
        RecoveryObservation::SourceStillPresent { source }
            if source.exists
                && source
                    .identity
                    .as_ref()
                    .is_some_and(|value| !value.is_empty()) =>
        {
            Ok((
                RecoveryDisposition::Reserved,
                "source still present; reserved intent cannot be replayed".to_string(),
            ))
        }
        RecoveryObservation::SourceAbsentDestinationConfirmed { destination }
            if mode == RequestedMode::Trash
                && destination.exists
                && destination
                    .identity
                    .as_ref()
                    .is_some_and(|value| !value.is_empty()) =>
        {
            Ok((
                RecoveryDisposition::Pending,
                "source absent and trash destination confirmed".to_string(),
            ))
        }
        RecoveryObservation::SourceStillPresent { .. }
        | RecoveryObservation::SourceAbsentDestinationConfirmed { .. } => {
            Err(AuditError::InvalidObservation)
        }
        RecoveryObservation::SourceAbsentDestinationUnconfirmed => Ok((
            RecoveryDisposition::Indeterminate,
            "source absent and destination unconfirmed".to_string(),
        )),
        RecoveryObservation::Unknown => Ok((
            RecoveryDisposition::Indeterminate,
            "observer could not confirm a safe recovery classification".to_string(),
        )),
    }
}

fn verify_snapshot(snapshot: &SnapshotFile) -> Result<(), AuditError> {
    if snapshot.version != SNAPSHOT_VERSION {
        return Err(AuditError::HeadMismatch);
    }
    if snapshot.events.len() > MAX_EVENTS
        || snapshot.projection.authorizations.len() > MAX_AUTHORIZATIONS
        || snapshot.projection.intents.len() > MAX_INTENTS
        || snapshot.projection.outcomes.len() > snapshot.projection.intents.len()
        || snapshot.projection.recoveries.len() > snapshot.projection.intents.len()
    {
        return Err(AuditError::StateTooLarge);
    }
    let mut projection = Projection::default();
    let mut previous_digest: Option<String> = None;
    let mut action_sequence = 0_u64;
    for (index, record) in snapshot.events.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(AuditError::HeadMismatch)?;
        if record.sequence != expected_sequence {
            return Err(AuditError::JournalTampered {
                sequence: record.sequence,
                reason: "non-monotonic sequence".to_string(),
            });
        }
        if record.previous_digest != previous_digest {
            return Err(AuditError::JournalTampered {
                sequence: record.sequence,
                reason: "previous digest mismatch".to_string(),
            });
        }
        let payload_json = canonical_json(&record.payload)?;
        if canonical_json(record)?.len() > MAX_EVENT_BYTES {
            return Err(AuditError::RecordTooLarge);
        }
        let expected_digest = digest_record(
            record.sequence,
            &record.recorded_at_unix_ms,
            &record.monotonic_elapsed_ms,
            record.previous_digest.as_deref(),
            &payload_json,
        );
        if record.digest != expected_digest {
            return Err(AuditError::JournalTampered {
                sequence: record.sequence,
                reason: "record digest mismatch".to_string(),
            });
        }
        apply_payload(&mut projection, &record.payload)?;
        if matches!(
            record.payload,
            EventPayload::ActionIntent(_)
                | EventPayload::ActionOutcome(_)
                | EventPayload::RecoveryOutcome(_)
        ) {
            action_sequence = action_sequence
                .checked_add(1)
                .ok_or(AuditError::HeadMismatch)?;
        }
        previous_digest = Some(record.digest.clone());
    }
    let expected_latest =
        u64::try_from(snapshot.events.len()).map_err(|_| AuditError::HeadMismatch)?;
    if snapshot.head.latest_sequence != expected_latest
        || snapshot.head.latest_digest != previous_digest
        || snapshot.head.action_sequence != action_sequence
        || snapshot.projection != projection
    {
        return Err(AuditError::HeadMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorComparison {
    Current,
    SnapshotOneAhead,
}

fn verify_anchor(anchor: &DurableAnchor) -> Result<(), AuditError> {
    if anchor.version != ANCHOR_VERSION
        || anchor.action_sequence > anchor.latest_sequence
        || (anchor.latest_sequence == 0) != anchor.latest_digest.is_none()
    {
        return Err(AuditError::RollbackDetected);
    }
    Ok(())
}

fn compare_anchor(
    snapshot: &SnapshotFile,
    anchor: &DurableAnchor,
) -> Result<AnchorComparison, AuditError> {
    if snapshot.head.latest_sequence == anchor.latest_sequence
        && snapshot.head.latest_digest == anchor.latest_digest
        && snapshot.head.action_sequence == anchor.action_sequence
    {
        return Ok(AnchorComparison::Current);
    }
    if snapshot.head.latest_sequence != anchor.latest_sequence.saturating_add(1) {
        return Err(AuditError::RollbackDetected);
    }
    let extension = snapshot.events.last().ok_or(AuditError::RollbackDetected)?;
    let action_increment = u64::from(matches!(
        extension.payload,
        EventPayload::ActionIntent(_)
            | EventPayload::ActionOutcome(_)
            | EventPayload::RecoveryOutcome(_)
    ));
    if extension.sequence != snapshot.head.latest_sequence
        || extension.previous_digest != anchor.latest_digest
        || snapshot.head.action_sequence != anchor.action_sequence + action_increment
    {
        return Err(AuditError::RollbackDetected);
    }
    Ok(AnchorComparison::SnapshotOneAhead)
}

fn apply_payload(projection: &mut Projection, payload: &EventPayload) -> Result<(), AuditError> {
    match payload {
        EventPayload::AuthorizationRegistered { binding } => {
            validate_binding(binding)?;
            if projection.authorizations.len() >= MAX_AUTHORIZATIONS {
                return Err(AuditError::StateTooLarge);
            }
            if projection
                .authorizations
                .contains_key(&binding.authorization_id)
            {
                return Err(AuditError::JournalTampered {
                    sequence: 0,
                    reason: "duplicate authorization registration".to_string(),
                });
            }
            projection.authorizations.insert(
                binding.authorization_id.clone(),
                AuthorizationRecord {
                    binding: binding.clone(),
                    state: AuthorizationState::Unused,
                },
            );
        }
        EventPayload::ExecutionClaimed {
            authorization_id,
            expected_plan_digest,
            fence_epoch,
        } => {
            let expected_epoch = projection
                .latest_fence_epoch
                .checked_add(1)
                .ok_or(AuditError::FenceEpochOverflow)?;
            if *fence_epoch != expected_epoch {
                return Err(AuditError::FenceEpochMismatch);
            }
            let record = projection
                .authorizations
                .get_mut(authorization_id)
                .ok_or_else(|| {
                    AuditError::AuthorizationUnknown(authorization_id.as_str().to_string())
                })?;
            if &record.binding.plan_digest != expected_plan_digest {
                return Err(AuditError::PlanDigestMismatch);
            }
            if record.state != AuthorizationState::Unused {
                return Err(AuditError::AuthorizationAlreadyClaimed(
                    authorization_id.as_str().to_string(),
                ));
            }
            record.state = AuthorizationState::Claimed {
                fence_epoch: *fence_epoch,
            };
            projection.latest_fence_epoch = *fence_epoch;
        }
        EventPayload::RecoveryClaimed {
            authorization_id,
            expected_plan_digest,
            previous_fence_epoch,
            fence_epoch,
        } => {
            let expected_epoch = projection
                .latest_fence_epoch
                .checked_add(1)
                .ok_or(AuditError::FenceEpochOverflow)?;
            if *fence_epoch != expected_epoch {
                return Err(AuditError::FenceEpochMismatch);
            }
            let record = projection
                .authorizations
                .get_mut(authorization_id)
                .ok_or_else(|| {
                    AuditError::AuthorizationUnknown(authorization_id.as_str().to_string())
                })?;
            if &record.binding.plan_digest != expected_plan_digest {
                return Err(AuditError::PlanDigestMismatch);
            }
            if record.state
                != (AuthorizationState::Claimed {
                    fence_epoch: *previous_fence_epoch,
                })
            {
                return Err(AuditError::FenceEpochMismatch);
            }
            record.state = AuthorizationState::Claimed {
                fence_epoch: *fence_epoch,
            };
            projection.latest_fence_epoch = *fence_epoch;
        }
        EventPayload::ActionIntent(event) => apply_intent(projection, event)?,
        EventPayload::ActionOutcome(event) => apply_outcome(projection, event, false)?,
        EventPayload::RecoveryOutcome(event) => apply_outcome(projection, event, true)?,
        EventPayload::RecoveryClassification {
            record,
            claim_fence_epoch,
        } => {
            validate_current_claim(projection, &record.authorization_id, *claim_fence_epoch)?;
            let authority = projection.intents.get(&record.attempt_id).ok_or_else(|| {
                AuditError::IntentNotFound(record.attempt_id.as_str().to_string())
            })?;
            if authority.authorization_id != record.authorization_id
                || authority.batch_id != record.batch_id
                || authority.action_id != record.action_id
                || authority.terminal_state == IntentTerminalState::OutcomeRecorded
                || record.reason.len() > MAX_TEXT_BYTES
            {
                return Err(AuditError::AuthorizationBindingMismatch);
            }
            projection
                .recoveries
                .insert(record.attempt_id.clone(), record.clone());
        }
        EventPayload::ExecutionConsumed {
            authorization_id,
            fence_epoch,
        } => {
            validate_current_claim(projection, authorization_id, *fence_epoch)?;
            if projection.intents.values().any(|intent| {
                intent.authorization_id == *authorization_id
                    && intent.terminal_state != IntentTerminalState::OutcomeRecorded
            }) {
                return Err(AuditError::UnresolvedIntentsRemain);
            }
            projection
                .authorizations
                .get_mut(authorization_id)
                .expect("validated above")
                .state = AuthorizationState::Consumed {
                fence_epoch: *fence_epoch,
            };
        }
    }
    Ok(())
}

fn apply_intent(projection: &mut Projection, event: &IntentEvent) -> Result<(), AuditError> {
    if projection.intents.len() >= MAX_INTENTS {
        return Err(AuditError::StateTooLarge);
    }
    validate_current_claim(projection, &event.authorization_id, event.fence_epoch)?;
    let authorization = projection
        .authorizations
        .get(&event.authorization_id)
        .expect("validated above");
    validate_intent_event(&authorization.binding, event)?;
    let expected_ordinal = projection
        .next_attempt_ordinal
        .checked_add(1)
        .ok_or(AuditError::FenceEpochOverflow)?;
    if event.attempt_ordinal != expected_ordinal
        || event.attempt_id.as_str()
            != derive_digest_id(
                "attempt",
                &event.authorization_id,
                event.fence_epoch,
                event.attempt_ordinal,
            )
        || event.nonce.as_str()
            != derive_digest_id(
                "nonce",
                &event.authorization_id,
                event.fence_epoch,
                event.attempt_ordinal,
            )
        || projection.intents.contains_key(&event.attempt_id)
        || projection.intents.values().any(|intent| {
            intent.authorization_id == event.authorization_id && intent.action_id == event.action_id
        })
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    projection.next_attempt_ordinal = event.attempt_ordinal;
    projection.intents.insert(
        event.attempt_id.clone(),
        IntentAuthority {
            attempt_id: event.attempt_id.clone(),
            nonce: event.nonce.clone(),
            authorization_id: event.authorization_id.clone(),
            batch_id: event.batch_id.clone(),
            plan_id: event.plan_id.clone(),
            plan_digest: event.plan_digest.clone(),
            item_id: event.item_id.clone(),
            action_id: event.action_id.clone(),
            requested_mode: event.requested_mode,
            risk_tier: event.risk_tier,
            source_path_hash: event.source_path_hash.clone(),
            before_revalidation_digest: event.before_revalidation_digest.clone(),
            fence_epoch: event.fence_epoch,
            attempt_ordinal: event.attempt_ordinal,
            terminal_state: IntentTerminalState::Reserved,
        },
    );
    Ok(())
}

fn apply_outcome(
    projection: &mut Projection,
    event: &OutcomeEvent,
    recovery_resolution: bool,
) -> Result<(), AuditError> {
    validate_current_claim(projection, &event.authorization_id, event.claim_fence_epoch)?;
    let binding = &projection
        .authorizations
        .get(&event.authorization_id)
        .expect("validated above")
        .binding;
    if event.authorization_source != binding.authorization_source
        || event.policy_version != binding.policy_version
        || event.policy_digest != binding.policy_digest
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    let authority = projection
        .intents
        .get_mut(&event.attempt_id)
        .ok_or_else(|| AuditError::IntentNotFound(event.attempt_id.as_str().to_string()))?;
    let existing_outcome = projection.outcomes.get(&event.attempt_id);
    let can_replace_indeterminate = recovery_resolution
        && authority.terminal_state == IntentTerminalState::IndeterminateRecorded
        && existing_outcome.is_some_and(outcome_is_indeterminate);
    if !matches!(
        authority.terminal_state,
        IntentTerminalState::Reserved | IntentTerminalState::IndeterminateRecorded
    ) || existing_outcome.is_some() && !can_replace_indeterminate
        || !outcome_matches_authority(event, authority)
        || recovery_resolution && event.claim_fence_epoch <= authority.fence_epoch
        || !recovery_resolution && event.claim_fence_epoch != authority.fence_epoch
    {
        return Err(AuditError::OutcomeAlreadyExists(
            event.attempt_id.as_str().to_string(),
        ));
    }
    validate_outcome_event(event)?;
    authority.terminal_state = if event.recovery_state == RecoveryState::Indeterminate {
        IntentTerminalState::IndeterminateRecorded
    } else {
        IntentTerminalState::OutcomeRecorded
    };
    projection
        .outcomes
        .insert(event.attempt_id.clone(), event.clone());
    Ok(())
}

fn outcome_is_indeterminate(event: &OutcomeEvent) -> bool {
    event.recovery_state == RecoveryState::Indeterminate
}

fn validate_current_claim(
    projection: &Projection,
    authorization_id: &AuthorizationId,
    fence_epoch: u64,
) -> Result<(), AuditError> {
    let record = projection
        .authorizations
        .get(authorization_id)
        .ok_or_else(|| AuditError::AuthorizationUnknown(authorization_id.as_str().to_string()))?;
    if record.state != (AuthorizationState::Claimed { fence_epoch }) {
        return Err(AuditError::FenceEpochMismatch);
    }
    Ok(())
}

fn ensure_private_state_dir(root: &Path) -> Result<(), AuditError> {
    if !root.is_absolute() {
        return Err(AuditError::StateDirNotAbsolute);
    }
    for component in root.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            _ => return Err(AuditError::UnsafeStateDir(root.display().to_string())),
        }
    }
    reject_symlink_ancestors(root)?;
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(AuditError::SymlinkRejected(root.display().to_string()));
            }
            if !metadata.is_dir() {
                return Err(AuditError::UnsafeStateDir(root.display().to_string()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_private_dir(root)?,
        Err(error) => return Err(AuditError::Io(error)),
    }
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Err(AuditError::SymlinkRejected(root.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        let current_uid = unsafe { libc::geteuid() };
        if mode & 0o077 != 0 || metadata.uid() != current_uid {
            return Err(AuditError::StateDirNotPrivate(root.display().to_string()));
        }
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), AuditError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(AuditError::UnsupportedPlatform)
    }
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), AuditError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AuditError::SymlinkRejected(current.display().to_string()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(AuditError::Io(error)),
        }
    }
    Ok(())
}

fn cleanup_stale_snapshot_temps(dir: &File, root: &Path) -> Result<(), AuditError> {
    validate_directory_descriptor(dir, root)?;
    for name in directory_entry_names(dir)? {
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_snapshot_tmp = name.starts_with(".audit.snapshot.");
        let is_anchor_tmp = name.starts_with(".audit.anchor.");
        if (!is_snapshot_tmp && !is_anchor_tmp) || !name.ends_with(".tmp") {
            continue;
        }
        let _file = openat_file(dir, name, false)?;
        unlinkat_file(dir, name)?;
    }
    validate_directory_descriptor(dir, root)?;
    dir.sync_all()?;
    Ok(())
}

fn regular_file_exists_at(dir: &File, name: &str) -> Result<bool, AuditError> {
    match openat_file(dir, name, false) {
        Ok(_) => Ok(true),
        Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn ensure_regular_file_at(dir: &File, name: &str, initial: &[u8]) -> Result<(), AuditError> {
    match openat_file(dir, name, true) {
        Ok(_) => Ok(()),
        Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = createat_file(dir, name)?;
            file.write_all(initial)?;
            file.sync_all()?;
            dir.sync_all()?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn validate_lock_descriptor(file: &File, dir: &File) -> Result<(), AuditError> {
    validate_open_file_descriptor(file)?;
    let entry = openat_file(dir, LOCK_FILE, true)?;
    ensure_same_file(file, &entry, LOCK_FILE)
}

fn read_json_file_at<T: for<'de> Deserialize<'de>>(
    dir: &File,
    name: &str,
    max_bytes: usize,
) -> Result<T, std::io::Error> {
    let mut file = openat_file(dir, name, false).map_err(std::io::Error::other)?;
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes as u64 {
        return Err(std::io::Error::other("file too large"));
    }
    let mut buf = Vec::with_capacity(metadata.len() as usize + 1);
    file.read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(std::io::Error::other("file too large"));
    }
    serde_json::from_slice(&buf).map_err(|error| std::io::Error::other(error.to_string()))
}

fn open_directory_nofollow(path: &Path) -> Result<File, AuditError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(Path::new("/"))?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat_directory(&directory, name)?;
            }
            _ => return Err(AuditError::UnsafeStateDir(path.display().to_string())),
        }
    }
    validate_directory_descriptor(&directory, path)?;
    Ok(directory)
}

fn validate_directory_descriptor(file: &File, path: &Path) -> Result<(), AuditError> {
    let descriptor = file.metadata()?;
    let entry = fs::symlink_metadata(path)?;
    if entry.file_type().is_symlink() || !descriptor.is_dir() || !entry.is_dir() {
        return Err(AuditError::SymlinkRejected(path.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if descriptor.dev() != entry.dev()
            || descriptor.ino() != entry.ino()
            || descriptor.uid() != unsafe { libc::geteuid() }
            || descriptor.mode() & 0o077 != 0
        {
            return Err(AuditError::StateDirNotPrivate(path.display().to_string()));
        }
    }
    Ok(())
}

fn openat_directory(dir: &File, name: &std::ffi::OsStr) -> Result<File, AuditError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| AuditError::UnsafeStateDir(name.to_string_lossy().into_owned()))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(AuditError::SymlinkRejected(
                name.to_string_lossy().into_owned(),
            ));
        }
        return Err(AuditError::Io(error));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_dir() {
        return Err(AuditError::UnsafeStateDir(
            name.to_string_lossy().into_owned(),
        ));
    }
    Ok(file)
}

fn directory_entry_names(dir: &File) -> Result<Vec<std::ffi::OsString>, AuditError> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;

    let duplicate = unsafe { libc::dup(dir.as_raw_fd()) };
    if duplicate < 0 {
        return Err(AuditError::Io(std::io::Error::last_os_error()));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(AuditError::Io(std::io::Error::last_os_error()));
    }
    let mut names = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(std::ffi::OsString::from_vec(bytes.to_vec()));
        }
    }
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(AuditError::Io(std::io::Error::last_os_error()));
    }
    Ok(names)
}

fn c_name(name: &str) -> Result<std::ffi::CString, AuditError> {
    std::ffi::CString::new(name).map_err(|_| AuditError::UnsafeStateDir(name.to_string()))
}

fn openat_file(dir: &File, name: &str, write: bool) -> Result<File, AuditError> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = c_name(name)?;
    let access = if write { libc::O_RDWR } else { libc::O_RDONLY };
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            access | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(AuditError::SymlinkRejected(
                name.to_string_lossy().into_owned(),
            ));
        }
        return Err(AuditError::Io(error));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    validate_open_file_descriptor(&file)?;
    Ok(file)
}

fn createat_file(dir: &File, name: &str) -> Result<File, AuditError> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = c_name(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    if fd < 0 {
        return Err(AuditError::Io(std::io::Error::last_os_error()));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    validate_open_file_descriptor(&file)?;
    Ok(file)
}

fn validate_open_file_descriptor(file: &File) -> Result<(), AuditError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(AuditError::StateDirNotPrivate("audit file".to_string()));
    }
    Ok(())
}

fn ensure_same_file(left: &File, right: &File, name: &str) -> Result<(), AuditError> {
    use std::os::unix::fs::MetadataExt;

    let left = left.metadata()?;
    let right = right.metadata()?;
    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(AuditError::SymlinkRejected(name.to_string()));
    }
    Ok(())
}

fn renameat_file(dir: &File, from: &str, to: &str) -> Result<(), AuditError> {
    use std::os::fd::AsRawFd;

    let from = c_name(from)?;
    let to = c_name(to)?;
    let result =
        unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) };
    if result < 0 {
        return Err(AuditError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn unlinkat_file(dir: &File, name: &str) -> Result<(), AuditError> {
    use std::os::fd::AsRawFd;

    let name = c_name(name)?;
    let result = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if result < 0 {
        return Err(AuditError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn atomic_replace_named_at(dir: &File, target: &str, bytes: &[u8]) -> Result<(), AuditError> {
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(AuditError::StateTooLarge);
    }
    let ordinal = TEMP_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{target}.{}.{}.tmp", std::process::id(), ordinal);
    let mut file = createat_file(dir, &tmp_name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    renameat_file(dir, &tmp_name, target)?;
    dir.sync_all()?;
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, AuditError> {
    serde_jcs::to_string(value)
        .map_err(|error| AuditError::Io(std::io::Error::other(error.to_string())))
}

fn derive_digest_id(
    label: &str,
    authorization_id: &AuthorizationId,
    fence_epoch: u64,
    ordinal: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(b"\0");
    hasher.update(authorization_id.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(fence_epoch.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(ordinal.to_string().as_bytes());
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

pub fn hash_native_path(path: &Path) -> Result<PathHash, AuditError> {
    if !path.is_absolute() {
        return Err(AuditError::UnsafeStateDir(path.display().to_string()));
    }
    let mut hasher = Sha256::new();
    hasher.update(PATH_HASH_DOMAIN.as_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(path.as_os_str().as_bytes());
    }
    #[cfg(not(unix))]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in path.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
    }
    PathHash::new(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

fn digest_record(
    sequence: u64,
    recorded_at_unix_ms: &str,
    monotonic_elapsed_ms: &str,
    previous_digest: Option<&str>,
    payload_json: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN.as_bytes());
    hasher.update(sequence.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(recorded_at_unix_ms.as_bytes());
    hasher.update(b"\n");
    hasher.update(monotonic_elapsed_ms.as_bytes());
    hasher.update(b"\n");
    if let Some(previous) = previous_digest {
        hasher.update(previous.as_bytes());
    }
    hasher.update(b"\n");
    hasher.update(payload_json.as_bytes());
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

fn parse_decimal_u64(value: &str) -> Result<u64, AuditError> {
    value.parse::<u64>().map_err(|_| AuditError::HeadMismatch)
}

fn unix_ms_string(time: SystemTime) -> Result<String, AuditError> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuditError::InvalidClock)?
        .as_millis()
        .to_string())
}

fn monotonic_elapsed_ms_string() -> String {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    let elapsed: Duration = start.elapsed();
    elapsed.as_millis().to_string()
}

fn bounded_notes(notes: Vec<String>) -> Result<Vec<String>, AuditError> {
    if notes.len() > MAX_NOTES || notes.iter().any(|note| note.len() > MAX_NOTE_BYTES) {
        return Err(AuditError::RecordTooLarge);
    }
    Ok(notes)
}

fn validate_stable_id(value: &str, field: &'static str) -> Result<(), AuditError> {
    let valid_length = (8..=160).contains(&value.len());
    let valid_chars = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'));
    if valid_length && valid_chars {
        Ok(())
    } else {
        Err(AuditError::InvalidStableId { field })
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::TempDir;

    fn private_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn store() -> (TempDir, AuditStore) {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        private_dir(&root);
        let store = AuditStore::open(&root).unwrap();
        (temp, store)
    }

    fn binding(
        index: u8,
        mode: RequestedMode,
        source: AuthorizationSource,
        risk: RiskTier,
    ) -> AuthorizationBinding {
        let authorization_id = AuthorizationId::new(format!("auth-{index:02}-sha256")).unwrap();
        let batch_id = BatchId::new(format!("batch-{index:02}-sha256")).unwrap();
        let plan_id = PlanId::new(format!("plan-{index:02}-sha256")).unwrap();
        let plan_digest = DigestString::new(format!("plan-digest-{index:02}-sha256")).unwrap();
        let item_id = ItemId::new(format!("item-{index:02}-sha256")).unwrap();
        let action_id = ActionId::new(format!("action-{index:02}-sha256")).unwrap();
        let mut item_ids = BTreeSet::new();
        item_ids.insert(item_id.clone());
        let mut action_ids = BTreeSet::new();
        action_ids.insert(action_id.clone());
        let mut risk_by_action = BTreeMap::new();
        risk_by_action.insert(action_id.clone(), risk);
        let mut item_by_action = BTreeMap::new();
        item_by_action.insert(action_id, item_id.clone());
        AuthorizationBinding {
            authorization_id,
            authorization_source: source,
            batch_id,
            plan_id,
            plan_digest,
            requested_mode: mode,
            item_ids,
            action_ids,
            item_by_action,
            action_count: 1,
            risk_by_action,
            policy_version: "policy-v1".to_string(),
            policy_digest: DigestString::new(format!("policy-{index:02}-sha256")).unwrap(),
            protected_anchor_snapshot_digest: DigestString::new(format!(
                "anchors-{index:02}-sha256"
            ))
            .unwrap(),
            adapter_capabilities_digest: DigestString::new(format!("adapter-{index:02}-sha256"))
                .unwrap(),
            cleaner_set_digest: DigestString::new(format!("cleaner-{index:02}-sha256")).unwrap(),
            host_instance_id: HostId::new(format!("host-{index:02}-sha256")).unwrap(),
            user_identity: UserId::new(format!("user-{index:02}-sha256")).unwrap(),
            workflow_session: SessionId::new(format!("session-{index:02}-sha256")).unwrap(),
        }
    }

    fn register_and_claim(store: &AuditStore, binding: AuthorizationBinding) -> ClaimedExecution {
        store
            .register_authorization(RegisterAuthorization {
                binding: binding.clone(),
            })
            .unwrap();
        store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap()
    }

    fn intent_request(index: u8, binding: &AuthorizationBinding) -> IntentRequest {
        IntentRequest {
            item_id: binding.item_ids.iter().next().unwrap().clone(),
            action_id: binding.action_ids.iter().next().unwrap().clone(),
            source_path_hash: PathHash::new(format!("path-{index:02}-sha256")).unwrap(),
            before_revalidation_digest: DigestString::new(format!("reval-{index:02}-sha256"))
                .unwrap(),
        }
    }

    fn permanent_success() -> SimulatedOutcome {
        SimulatedOutcome::permanent_success(
            "adapter-v1",
            UNIX_EPOCH + Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(2),
            Observation {
                exists: false,
                identity: None,
            },
            "ok",
            Vec::new(),
        )
        .unwrap()
    }

    fn append_test_event(snapshot: &mut SnapshotFile, payload: EventPayload) {
        let sequence = snapshot.head.latest_sequence + 1;
        let recorded_at = "1".to_string();
        let monotonic = "1".to_string();
        let payload_json = canonical_json(&payload).unwrap();
        let digest = digest_record(
            sequence,
            &recorded_at,
            &monotonic,
            snapshot.head.latest_digest.as_deref(),
            &payload_json,
        );
        apply_payload(&mut snapshot.projection, &payload).unwrap();
        if matches!(
            payload,
            EventPayload::ActionIntent(_) | EventPayload::ActionOutcome(_)
        ) {
            snapshot.head.action_sequence += 1;
        }
        snapshot.events.push(JournalRecord {
            sequence,
            recorded_at_unix_ms: recorded_at,
            monotonic_elapsed_ms: monotonic,
            previous_digest: snapshot.head.latest_digest.clone(),
            digest: digest.clone(),
            payload,
        });
        snapshot.head.latest_sequence = sequence;
        snapshot.head.latest_digest = Some(digest);
        verify_snapshot(snapshot).unwrap();
    }

    struct FixedObserver(RecoveryObservation);

    impl RecoveryObserver for FixedObserver {
        fn observe(&self, _intent: &RecoveryIntentView) -> Result<RecoveryObservation, AuditError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn symlink_state_dir_rejected() {
        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        private_dir(&real);
        let link = temp.path().join("link");
        symlink(&real, &link).unwrap();
        let error = AuditStore::open(&link).unwrap_err();
        assert!(matches!(error, AuditError::SymlinkRejected(_)));
    }

    #[test]
    fn symlink_snapshot_rejected() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        private_dir(&root);
        let external = temp.path().join("external");
        File::create(&external).unwrap();
        symlink(&external, root.join(SNAPSHOT_FILE)).unwrap();
        let error = AuditStore::open(&root).unwrap_err();
        assert!(matches!(error, AuditError::SymlinkRejected(_)));
    }

    #[test]
    fn anchor_repairs_only_one_valid_snapshot_event_ahead() {
        let (temp, store) = store();
        let mut snapshot = store.read_verified_snapshot().unwrap();
        let binding = binding(
            21,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        append_test_event(
            &mut snapshot,
            EventPayload::AuthorizationRegistered { binding },
        );
        atomic_replace_named_at(
            &store.state_dir,
            SNAPSHOT_FILE,
            canonical_json(&snapshot).unwrap().as_bytes(),
        )
        .unwrap();
        drop(store);

        let reopened = AuditStore::open(temp.path().join("audit")).unwrap();
        assert_eq!(reopened.verify_integrity().unwrap().latest_sequence, 1);
        let anchor: DurableAnchor =
            read_json_file_at(&reopened.state_dir, ANCHOR_FILE, MAX_ANCHOR_BYTES).unwrap();
        assert_eq!(anchor.latest_sequence, 1);
        assert_eq!(anchor.latest_digest, snapshot.head.latest_digest);
    }

    #[test]
    fn anchor_rejects_snapshot_rollback_and_two_event_gap() {
        let (temp, first_store) = store();
        let genesis = fs::read(first_store.root.join(SNAPSHOT_FILE)).unwrap();
        let first = binding(
            22,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        first_store
            .register_authorization(RegisterAuthorization { binding: first })
            .unwrap();
        fs::write(first_store.root.join(SNAPSHOT_FILE), &genesis).unwrap();
        drop(first_store);
        assert!(matches!(
            AuditStore::open(temp.path().join("audit")),
            Err(AuditError::RollbackDetected)
        ));

        let (temp, store) = store();
        let mut snapshot = store.read_verified_snapshot().unwrap();
        for index in [23, 24] {
            append_test_event(
                &mut snapshot,
                EventPayload::AuthorizationRegistered {
                    binding: binding(
                        index,
                        RequestedMode::Permanent,
                        AuthorizationSource::DeterministicSimulation,
                        RiskTier::R4,
                    ),
                },
            );
        }
        atomic_replace_named_at(
            &store.state_dir,
            SNAPSHOT_FILE,
            canonical_json(&snapshot).unwrap().as_bytes(),
        )
        .unwrap();
        drop(store);
        assert!(matches!(
            AuditStore::open(temp.path().join("audit")),
            Err(AuditError::RollbackDetected)
        ));
    }

    #[test]
    fn interrupted_empty_store_initialization_recovers() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        private_dir(&root);
        let dir = open_directory_nofollow(&root).unwrap();
        ensure_regular_file_at(&dir, LOCK_FILE, b"lock\n").unwrap();
        drop(dir);
        let store = AuditStore::open(&root).unwrap();
        assert_eq!(store.verify_integrity().unwrap().latest_sequence, 0);
    }

    #[test]
    fn anchor_rejects_ahead_or_divergent_head() {
        let (temp, store) = store();
        let mut anchor: DurableAnchor =
            read_json_file_at(&store.state_dir, ANCHOR_FILE, MAX_ANCHOR_BYTES).unwrap();
        anchor.latest_sequence = 1;
        anchor.latest_digest = Some("sha256:anchor-ahead".to_string());
        atomic_replace_named_at(
            &store.state_dir,
            ANCHOR_FILE,
            canonical_json(&anchor).unwrap().as_bytes(),
        )
        .unwrap();
        drop(store);
        assert!(matches!(
            AuditStore::open(temp.path().join("audit")),
            Err(AuditError::RollbackDetected)
        ));
    }

    #[test]
    fn duplicate_claim_rejected() {
        let (_tmp, store) = store();
        let binding = binding(
            1,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        store
            .register_authorization(RegisterAuthorization {
                binding: binding.clone(),
            })
            .unwrap();
        store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let error = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap_err();
        assert!(matches!(error, AuditError::AuthorizationAlreadyClaimed(_)));
    }

    #[test]
    fn exact_binding_required_for_intent() {
        let (_tmp, store) = store();
        let binding = binding(
            2,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let claimed = register_and_claim(&store, binding.clone());
        let mut request = intent_request(2, &binding);
        request.action_id = ActionId::new("other-action-sha256").unwrap();
        let error = store.reserve_intent(&claimed, request).unwrap_err();
        assert!(matches!(error, AuditError::AuthorizationBindingMismatch));
    }

    #[test]
    fn reservation_reports_created_existing_and_conflicting() {
        let (_tmp, store) = store();
        let binding = binding(
            12,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let claimed = register_and_claim(&store, binding.clone());
        let request = intent_request(12, &binding);
        let created = store
            .reserve_intent_once(&claimed, request.clone())
            .unwrap();
        let IntentReservation::Created(token) = created else {
            panic!("first reservation must create authority");
        };
        let expected_attempt_id = token.attempt_id().clone();
        let existing = store
            .reserve_intent_once(&claimed, request.clone())
            .unwrap();
        let IntentReservation::Existing(existing) = existing else {
            panic!("exact retry must return diagnostics");
        };
        assert_eq!(existing.attempt_id(), &expected_attempt_id);
        assert_eq!(existing.item_id(), token.item_id());
        assert_eq!(existing.action_id(), token.action_id());
        let conflicting = store
            .reserve_intent_once(
                &claimed,
                IntentRequest {
                    source_path_hash: PathHash::new("changed-path-12-sha256").unwrap(),
                    ..request.clone()
                },
            )
            .unwrap();
        let IntentReservation::Conflicting(conflicting) = conflicting else {
            panic!("changed retry must return diagnostics");
        };
        assert_eq!(conflicting.attempt_id(), &expected_attempt_id);
        assert!(matches!(
            store.reserve_intent(
                &claimed,
                IntentRequest {
                    source_path_hash: PathHash::new("changed-path-12-sha256").unwrap(),
                    ..request
                }
            ),
            Err(AuditError::ActionAlreadyReserved(_))
        ));
    }

    #[test]
    fn outcome_requires_matching_durable_intent() {
        let (_tmp, store) = store();
        let binding = binding(
            3,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let claimed = register_and_claim(&store, binding.clone());
        let fake = DurableIntentToken {
            attempt_id: AttemptId::new("attempt-fake-sha256").unwrap(),
            nonce: NonceId::new("nonce-fake-sha256").unwrap(),
            authorization_id: binding.authorization_id.clone(),
            batch_id: binding.batch_id.clone(),
            plan_id: binding.plan_id.clone(),
            plan_digest: binding.plan_digest.clone(),
            item_id: binding.item_ids.iter().next().unwrap().clone(),
            action_id: binding.action_ids.iter().next().unwrap().clone(),
            requested_mode: binding.requested_mode,
            risk_tier: RiskTier::R4,
            source_path_hash: PathHash::new("path-fake-sha256").unwrap(),
            before_revalidation_digest: DigestString::new("reval-fake-sha256").unwrap(),
            fence_epoch: claimed.fence_epoch,
            creator_pid: std::process::id(),
        };
        let error = store
            .record_outcome(&claimed, &fake, permanent_success())
            .unwrap_err();
        assert!(matches!(error, AuditError::IntentNotFound(_)));
    }

    #[test]
    fn permanent_success_requires_source_absent_and_no_destination() {
        let error = SimulatedOutcome::permanent_success(
            "adapter-v1",
            UNIX_EPOCH + Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(2),
            Observation {
                exists: true,
                identity: Some("same".to_string()),
            },
            "ok",
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AuditError::SuccessRequiresSourceAbsent | AuditError::InvalidOutcome
        ));
    }

    #[test]
    fn trash_success_requires_platform_result_evidence() {
        let error = SimulatedOutcome::trash_success(
            "adapter-v1",
            UNIX_EPOCH + Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(2),
            Observation {
                exists: false,
                identity: None,
            },
            Observation {
                exists: false,
                identity: None,
            },
            None,
            "",
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(error, AuditError::InvalidOutcome));
    }

    #[test]
    fn every_status_requires_exact_recovery_and_evidence_tuple() {
        let absent = Observation {
            exists: false,
            identity: None,
        };
        let present = Observation {
            exists: true,
            identity: Some("same-object".to_string()),
        };
        let empty_identity = Observation {
            exists: true,
            identity: Some(String::new()),
        };
        assert!(
            validate_outcome_tuple(
                RequestedMode::Trash,
                StableStatus::TrashSucceededPlatformReported,
                RecoveryState::PlatformTrashReported,
                &absent,
                None,
                None,
                Some(&"ok".to_string()),
                None,
                None,
            )
            .is_ok()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Trash,
                StableStatus::TrashSucceededPlatformReported,
                RecoveryState::PlatformTrashReported,
                &absent,
                None,
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::FailedSourceUnchanged,
                RecoveryState::FailedSourceUnchanged,
                &present,
                None,
                None,
                Some(&"not-submitted".to_string()),
                None,
                None,
            )
            .is_ok()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::FailedSourceUnchanged,
                RecoveryState::FailedSourceUnchanged,
                &empty_identity,
                None,
                None,
                Some(&"not-submitted".to_string()),
                None,
                None,
            )
            .is_err()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::CancelledBeforeAction,
                RecoveryState::CancelledBeforeAction,
                &present,
                None,
                None,
                None,
                None,
                None,
            )
            .is_ok()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::VanishedBeforeAction,
                RecoveryState::VanishedBeforeAction,
                &absent,
                None,
                None,
                None,
                None,
                None,
            )
            .is_ok()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::FailedPlatformError,
                RecoveryState::Indeterminate,
                &absent,
                None,
                None,
                Some(&"failed".to_string()),
                Some(&"platform".to_string()),
                Some(&"EIO".to_string()),
            )
            .is_ok()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::FailedPlatformError,
                RecoveryState::Indeterminate,
                &absent,
                None,
                None,
                Some(&"failed".to_string()),
                None,
                Some(&"EIO".to_string()),
            )
            .is_err()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::IndeterminateAfterCrash,
                RecoveryState::Indeterminate,
                &absent,
                None,
                None,
                None,
                None,
                None,
            )
            .is_ok()
        );
        assert!(
            validate_outcome_tuple(
                RequestedMode::Permanent,
                StableStatus::IndeterminateAfterCrash,
                RecoveryState::Indeterminate,
                &absent,
                Some(&Observation {
                    exists: true,
                    identity: Some("success-like".to_string()),
                }),
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        for status in [
            StableStatus::TrashSucceededPlatformReported,
            StableStatus::TrashSucceededLocationReported,
            StableStatus::PermanentDeleteSucceeded,
            StableStatus::FailedPlatformError,
            StableStatus::FailedCancelledByPlatform,
            StableStatus::FailedSourceUnchanged,
            StableStatus::VanishedBeforeAction,
            StableStatus::CancelledBeforeAction,
            StableStatus::IndeterminateAfterCrash,
            StableStatus::IndeterminatePlatformResult,
        ] {
            assert!(
                validate_outcome_tuple(
                    RequestedMode::Permanent,
                    status,
                    RecoveryState::PlatformTrashReported,
                    &present,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn tamper_and_tail_truncation_detected() {
        let (_tmp, store) = store();
        let binding = binding(
            6,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let claimed = register_and_claim(&store, binding.clone());
        store
            .reserve_intent(&claimed, intent_request(6, &binding))
            .unwrap();
        assert!(store.verify_integrity().is_ok());

        let snapshot = store.root.join(SNAPSHOT_FILE);
        let mut contents = fs::read_to_string(&snapshot).unwrap();
        contents = contents.replace("permanent", "trash");
        fs::write(&snapshot, contents).unwrap();
        let error = store.verify_integrity().unwrap_err();
        assert!(matches!(
            error,
            AuditError::JournalTampered { .. } | AuditError::HeadMismatch
        ));
    }

    #[test]
    fn recovery_is_idempotent_and_no_marker_inference() {
        let (_tmp, store) = store();
        let binding = binding(
            7,
            RequestedMode::Trash,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R2,
        );
        let claimed = register_and_claim(&store, binding.clone());
        store
            .reserve_intent(&claimed, intent_request(7, &binding))
            .unwrap();
        let first = store
            .classify_recovery(&claimed, &FixedObserver(RecoveryObservation::Unknown))
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].disposition, RecoveryDisposition::Indeterminate);
        let second = store
            .classify_recovery(
                &claimed,
                &FixedObserver(RecoveryObservation::SourceStillPresent {
                    source: Observation {
                        exists: true,
                        identity: Some("same".to_string()),
                    },
                }),
            )
            .unwrap();
        assert_ne!(second, first);
        assert_eq!(second[0].disposition, RecoveryDisposition::Reserved);
        assert!(matches!(
            store.consume_execution(&claimed),
            Err(AuditError::UnresolvedIntentsRemain)
        ));
    }

    #[test]
    fn contradictory_recovery_observations_are_rejected() {
        assert!(matches!(
            classify_observation(
                RequestedMode::Permanent,
                RecoveryObservation::SourceStillPresent {
                    source: Observation {
                        exists: false,
                        identity: None,
                    },
                },
            ),
            Err(AuditError::InvalidObservation)
        ));
        assert!(matches!(
            classify_observation(
                RequestedMode::Trash,
                RecoveryObservation::SourceAbsentDestinationConfirmed {
                    destination: Observation {
                        exists: false,
                        identity: None,
                    },
                },
            ),
            Err(AuditError::InvalidObservation)
        ));
    }

    #[test]
    fn recovery_claim_can_record_original_intent_outcome() {
        let (_tmp, store) = store();
        let binding = binding(
            9,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let original = register_and_claim(&store, binding.clone());
        let token = store
            .reserve_intent(&original, intent_request(9, &binding))
            .unwrap();
        let original_epoch = original.fence_epoch();
        drop(original);

        let recovery = store
            .claim_recovery(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        assert!(recovery.fence_epoch() > original_epoch);
        let attempt_id = token.attempt_id().clone();
        drop(token);
        store
            .record_recovery_outcome(&recovery, &attempt_id, permanent_success())
            .unwrap();
        store.consume_execution(&recovery).unwrap();
        assert_eq!(store.verify_integrity().unwrap().latest_sequence, 6);
    }

    #[test]
    fn original_claim_cannot_use_tokenless_recovery_outcome() {
        let (_tmp, store) = store();
        let binding = binding(
            13,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let claimed = register_and_claim(&store, binding.clone());
        let token = store
            .reserve_intent(&claimed, intent_request(13, &binding))
            .unwrap();
        assert!(matches!(
            store.record_recovery_outcome(&claimed, token.attempt_id(), permanent_success()),
            Err(AuditError::RecoveryClaimRequired)
        ));
    }

    #[test]
    fn unresolved_same_path_across_authorizations_is_conflicting() {
        let (_tmp, store) = store();
        let first = binding(
            14,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let first_claim = register_and_claim(&store, first.clone());
        let first_token = store
            .reserve_intent(&first_claim, intent_request(14, &first))
            .unwrap();
        drop(first_claim);

        let second = binding(
            15,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        store
            .register_authorization(RegisterAuthorization {
                binding: second.clone(),
            })
            .unwrap();
        let second_claim = store
            .claim_execution(&second.authorization_id, &second.plan_digest)
            .unwrap();
        let mut request = intent_request(15, &second);
        request.source_path_hash = first_token.source_path_hash().clone();
        let reservation = store.reserve_intent_once(&second_claim, request).unwrap();
        let IntentReservation::Conflicting(info) = reservation else {
            panic!("same unresolved path must conflict across authorization boundaries");
        };
        assert_eq!(info.attempt_id(), first_token.attempt_id());
    }

    #[test]
    fn indeterminate_outcome_blocks_consume_and_cross_authorization_until_recovered() {
        let (_tmp, store) = store();
        let first = binding(
            16,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let first_claim = register_and_claim(&store, first.clone());
        let first_request = intent_request(16, &first);
        let source_path_hash = first_request.source_path_hash.clone();
        let first_token = store.reserve_intent(&first_claim, first_request).unwrap();
        let attempt_id = first_token.attempt_id().clone();
        let indeterminate = SimulatedOutcome::indeterminate_after_crash(
            RequestedMode::Permanent,
            "adapter-v1",
            UNIX_EPOCH + Duration::from_secs(1),
            UNIX_EPOCH + Duration::from_secs(2),
            Observation {
                exists: false,
                identity: None,
            },
            vec!["submission state unknown".to_string()],
        )
        .unwrap();
        store
            .record_outcome(&first_claim, &first_token, indeterminate)
            .unwrap();
        assert!(matches!(
            store.consume_execution(&first_claim),
            Err(AuditError::UnresolvedIntentsRemain)
        ));
        drop(first_token);
        drop(first_claim);

        let second = binding(
            17,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        store
            .register_authorization(RegisterAuthorization {
                binding: second.clone(),
            })
            .unwrap();
        let second_claim = store
            .claim_execution(&second.authorization_id, &second.plan_digest)
            .unwrap();
        let mut second_request = intent_request(17, &second);
        second_request.source_path_hash = source_path_hash.clone();
        let conflict = store
            .reserve_intent_once(&second_claim, second_request.clone())
            .unwrap();
        let IntentReservation::Conflicting(info) = conflict else {
            panic!("indeterminate target must remain globally blocked");
        };
        assert_eq!(info.attempt_id(), &attempt_id);
        drop(second_claim);

        let first_recovery = store
            .claim_recovery(&first.authorization_id, &first.plan_digest)
            .unwrap();
        store
            .record_recovery_outcome(&first_recovery, &attempt_id, permanent_success())
            .unwrap();
        store.consume_execution(&first_recovery).unwrap();
        drop(first_recovery);

        let second_recovery = store
            .claim_recovery(&second.authorization_id, &second.plan_digest)
            .unwrap();
        assert!(matches!(
            store
                .reserve_intent_once(&second_recovery, second_request)
                .unwrap(),
            IntentReservation::Created(_)
        ));
    }

    #[test]
    fn insecure_existing_state_paths_fail_closed() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            AuditStore::open(&root),
            Err(AuditError::StateDirNotPrivate(_))
        ));

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = AuditStore::open(&root).unwrap();
        drop(store);
        fs::set_permissions(root.join(SNAPSHOT_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            AuditStore::open(&root),
            Err(AuditError::StateDirNotPrivate(_))
        ));
    }

    #[test]
    fn insecure_existing_audit_file_fails_closed() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        private_dir(&root);
        let lock_path = root.join(LOCK_FILE);
        fs::write(&lock_path, b"lock\n").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            AuditStore::open(&root),
            Err(AuditError::StateDirNotPrivate(_))
        ));
    }

    #[test]
    fn integrity_reports_full_chain_and_action_sequences() {
        let (_tmp, store) = store();
        let binding = binding(
            10,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        let claimed = register_and_claim(&store, binding.clone());
        let before = store.verify_integrity().unwrap();
        assert_eq!(before.latest_sequence, 2);
        assert_eq!(before.action_sequence, 0);
        store
            .reserve_intent(&claimed, intent_request(10, &binding))
            .unwrap();
        let after = store.verify_integrity().unwrap();
        assert_eq!(after.latest_sequence, 3);
        assert_eq!(after.action_sequence, 1);
    }

    #[test]
    fn event_slot_reservation_keeps_recovery_outcome_and_consume_reachable() {
        let claimed_empty = Projection {
            authorizations: BTreeMap::from([(
                AuthorizationId::new("auth-capacity-sha256").unwrap(),
                AuthorizationRecord {
                    binding: binding(
                        18,
                        RequestedMode::Permanent,
                        AuthorizationSource::DeterministicSimulation,
                        RiskTier::R4,
                    ),
                    state: AuthorizationState::Claimed { fence_epoch: 1 },
                },
            )]),
            latest_fence_epoch: 1,
            ..Projection::default()
        };
        let claim_payload = EventPayload::RecoveryClaimed {
            authorization_id: AuthorizationId::new("auth-capacity-sha256").unwrap(),
            expected_plan_digest: DigestString::new("plan-digest-capacity").unwrap(),
            previous_fence_epoch: 1,
            fence_epoch: 2,
        };
        assert_eq!(
            required_future_event_slots(&claimed_empty, &claim_payload).unwrap(),
            1
        );

        let unresolved_authority = IntentAuthority {
            attempt_id: AttemptId::new("attempt-capacity-sha256").unwrap(),
            nonce: NonceId::new("nonce-capacity-sha256").unwrap(),
            authorization_id: AuthorizationId::new("auth-capacity-sha256").unwrap(),
            batch_id: BatchId::new("batch-capacity-sha256").unwrap(),
            plan_id: PlanId::new("plan-capacity-sha256").unwrap(),
            plan_digest: DigestString::new("plan-digest-capacity").unwrap(),
            item_id: ItemId::new("item-capacity-sha256").unwrap(),
            action_id: ActionId::new("action-capacity-sha256").unwrap(),
            requested_mode: RequestedMode::Permanent,
            risk_tier: RiskTier::R4,
            source_path_hash: PathHash::new("path-capacity-sha256").unwrap(),
            before_revalidation_digest: DigestString::new("reval-capacity-sha256").unwrap(),
            fence_epoch: 1,
            attempt_ordinal: 1,
            terminal_state: IntentTerminalState::Reserved,
        };
        let unresolved = Projection {
            intents: BTreeMap::from([(
                unresolved_authority.attempt_id.clone(),
                unresolved_authority,
            )]),
            ..claimed_empty
        };
        assert_eq!(
            required_future_event_slots(&unresolved, &claim_payload).unwrap(),
            3
        );
        let consume = EventPayload::ExecutionConsumed {
            authorization_id: AuthorizationId::new("auth-capacity-sha256").unwrap(),
            fence_epoch: 2,
        };
        assert_eq!(
            required_future_event_slots(&unresolved, &consume).unwrap(),
            0
        );

        let candidate_with_room = MAX_EVENTS - 4;
        assert_eq!(candidate_with_room + 1 + 3, MAX_EVENTS);
        assert!(candidate_with_room + 1 + 3 <= MAX_EVENTS);
        assert!(candidate_with_room + 2 + 3 > MAX_EVENTS);
    }

    #[test]
    fn nested_unknown_snapshot_field_is_rejected() {
        let (_tmp, store) = store();
        let snapshot_path = store.root.join(SNAPSHOT_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&snapshot_path).unwrap()).unwrap();
        value["projection"]["unexpected"] = serde_json::Value::Bool(true);
        fs::write(&snapshot_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            store.verify_integrity(),
            Err(AuditError::StateDecode(_))
        ));
    }

    #[test]
    fn nested_unknown_event_field_is_rejected() {
        let (_tmp, store) = store();
        let binding = binding(
            11,
            RequestedMode::Permanent,
            AuthorizationSource::DeterministicSimulation,
            RiskTier::R4,
        );
        store
            .register_authorization(RegisterAuthorization { binding })
            .unwrap();
        let snapshot_path = store.root.join(SNAPSHOT_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&snapshot_path).unwrap()).unwrap();
        value["events"][0]["payload"]["unexpected"] = serde_json::Value::Bool(true);
        fs::write(&snapshot_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            store.verify_integrity(),
            Err(AuditError::StateDecode(_))
        ));
    }

    #[test]
    fn concurrent_writer_denied() {
        let (_tmp, store) = store();
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(store.root.join(LOCK_FILE))
            .unwrap();
        lock.try_lock_exclusive().unwrap();
        let error = store
            .register_authorization(RegisterAuthorization {
                binding: binding(
                    8,
                    RequestedMode::Permanent,
                    AuthorizationSource::DeterministicSimulation,
                    RiskTier::R4,
                ),
            })
            .unwrap_err();
        assert!(matches!(error, AuditError::ConcurrentWriterDenied));
        lock.unlock().unwrap();
    }
}
