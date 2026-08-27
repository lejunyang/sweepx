// SQLite implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use rusqlite::config::DbConfig;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sweepx_protocol::{
    AuditActionProjection, AuditAuthorizationProjection, AuditBatchProjection, AuditItemProjection,
    AuditOutcomeRecoveryState, AuditProjectionSnapshot, AuditProjectionState,
    AuditRecoveryDisposition, AuditStableStatus, AuditTerminalOutcomeProjection,
};
use thiserror::Error;

const DATABASE_FILE: &str = "audit.db";
const LOCK_FILE: &str = "audit.lock";
const SCHEMA_VERSION: &str = "sweepx.audit.sqlite.v1";
const APPLICATION_ID: i64 = 0x5357_5841;
const USER_VERSION: i64 = 1;
const PAGE_SIZE: u64 = 4096;
const MAX_PAGE_COUNT: u64 = 16_384;
const MAX_DATABASE_BYTES: u64 = PAGE_SIZE * MAX_PAGE_COUNT;
const MAX_WAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_DATABASE_BYTES: u64 = MAX_DATABASE_BYTES + MAX_WAL_BYTES + 1024 * 1024;
const MAX_RECORD_BYTES: usize = 256 * 1024;
const MAX_BINDING_BYTES: usize = 192 * 1024;
const MAX_ID_BYTES: usize = 160;
const MAX_SHORT_FIELD_BYTES: usize = 512;
const MAX_RESULT_FIELD_BYTES: usize = 4096;
const MAX_NOTES: usize = 16;
const MAX_NOTE_BYTES: usize = 512;
const MAX_ACTIONS_PER_AUTHORIZATION: usize = 256;
const MAX_AUTHORIZATIONS: i64 = 4096;
const MAX_EVENTS: i64 = 100_000;
const RECORD_DOMAIN: &[u8] = b"SweepX SQLite audit event v1\0";
const PATH_HASH_DOMAIN: &[u8] = b"SweepX native path hash v1\0";

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
        value.parse::<u64>().map_err(serde::de::Error::custom)
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
    /// Authority issued only by the deterministic P3 simulation path.
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
    #[serde(with = "decimal_u64")]
    pub action_count: u64,
    /// The authoritative exact action-to-item relation. The keys must equal
    /// `action_ids`, and its values must cover exactly `item_ids`.
    pub item_by_action: BTreeMap<ActionId, ItemId>,
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

pub struct ClaimedExecution {
    binding: AuthorizationBinding,
    fence_epoch: u64,
    database_id: String,
    execution_id: String,
    database_path: PathBuf,
    lock_identity: LockIdentity,
    live_claim: Arc<LiveClaimAuthority>,
    _not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
}

impl fmt::Debug for ClaimedExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedExecution")
            .field("authorization_id", &self.binding.authorization_id)
            .field("batch_id", &self.binding.batch_id)
            .field("fence_epoch", &self.fence_epoch)
            .field("execution_id", &self.execution_id)
            .field("lock_held", &self.live_claim.active.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Drop for ClaimedExecution {
    fn drop(&mut self) {
        if self.live_claim.owner_pid == std::process::id() {
            let _guard = self
                .live_claim
                .coordinator
                .mutation_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            release_live_claim(&self.live_claim);
        }
    }
}

fn release_live_claim(live_claim: &LiveClaimAuthority) {
    let file = live_claim
        .lock_file
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(file) = file {
        let _ = FileExt::unlock(&file);
    }
    live_claim.active.store(false, Ordering::Release);
    live_claim
        .coordinator
        .active
        .store(false, Ordering::Release);
}

impl ClaimedExecution {
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
    pub fn binding(&self) -> &AuthorizationBinding {
        &self.binding
    }
    pub fn validate_current_process(&self) -> Result<(), AuditError> {
        if self.live_claim.owner_pid == std::process::id() {
            Ok(())
        } else {
            Err(AuditError::ForkedProcess)
        }
    }
    fn lock_mutation(&self) -> Result<MutexGuard<'_, ()>, AuditError> {
        self.validate_current_process()?;
        self.live_claim
            .coordinator
            .mutation_lock
            .lock()
            .map_err(|_| AuditError::SessionLockPoisoned)
    }
}

pub struct DurableIntentToken {
    attempt_id: AttemptId,
    nonce: NonceId,
    database_id: String,
    execution_id: String,
    authorization_id: AuthorizationId,
    authorization_source: AuthorizationSource,
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
    policy_version: String,
    policy_digest: DigestString,
    protected_anchor_snapshot_digest: DigestString,
    adapter_capabilities_digest: DigestString,
    cleaner_set_digest: DigestString,
    host_instance_id: HostId,
    user_identity: UserId,
    workflow_session: SessionId,
    creator_pid: u32,
    live_claim: Weak<LiveClaimAuthority>,
}

impl PartialEq for DurableIntentToken {
    fn eq(&self, other: &Self) -> bool {
        self.attempt_id == other.attempt_id
            && self.nonce == other.nonce
            && self.database_id == other.database_id
            && self.execution_id == other.execution_id
            && self.authorization_id == other.authorization_id
            && self.authorization_source == other.authorization_source
            && self.batch_id == other.batch_id
            && self.plan_id == other.plan_id
            && self.plan_digest == other.plan_digest
            && self.item_id == other.item_id
            && self.action_id == other.action_id
            && self.requested_mode == other.requested_mode
            && self.risk_tier == other.risk_tier
            && self.source_path_hash == other.source_path_hash
            && self.before_revalidation_digest == other.before_revalidation_digest
            && self.fence_epoch == other.fence_epoch
            && self.policy_version == other.policy_version
            && self.policy_digest == other.policy_digest
            && self.protected_anchor_snapshot_digest == other.protected_anchor_snapshot_digest
            && self.adapter_capabilities_digest == other.adapter_capabilities_digest
            && self.cleaner_set_digest == other.cleaner_set_digest
            && self.host_instance_id == other.host_instance_id
            && self.user_identity == other.user_identity
            && self.workflow_session == other.workflow_session
            && self.creator_pid == other.creator_pid
    }
}
impl Eq for DurableIntentToken {}

struct LiveClaimAuthority {
    active: AtomicBool,
    coordinator: Arc<SessionCoordinator>,
    lock_file: Mutex<Option<File>>,
    database_path: PathBuf,
    database_id: String,
    database_identity: FileIdentity,
    lock_path: PathBuf,
    lock_identity: LockIdentity,
    execution_id: String,
    authorization_id: AuthorizationId,
    fence_epoch: u64,
    owner_pid: u32,
}

#[derive(Debug)]
struct SessionCoordinator {
    active: AtomicBool,
    mutation_lock: Mutex<()>,
}

impl fmt::Debug for LiveClaimAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveClaimAuthority")
            .field("active", &self.active.load(Ordering::Acquire))
            .field("execution_id", &self.execution_id)
            .field("fence_epoch", &self.fence_epoch)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DurableIntentToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableIntentToken")
            .field("attempt_id", &self.attempt_id)
            .field("nonce", &"<redacted>")
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
        let live_claim = self
            .live_claim
            .upgrade()
            .ok_or(AuditError::ClaimNotActive)?;
        if live_claim.owner_pid != std::process::id() {
            return Err(AuditError::ForkedProcess);
        }
        let _guard = live_claim
            .coordinator
            .mutation_lock
            .lock()
            .map_err(|_| AuditError::SessionLockPoisoned)?;
        if !live_claim.active.load(Ordering::Acquire) {
            return Err(AuditError::ClaimNotActive);
        }
        let lock_file = live_claim
            .lock_file
            .lock()
            .map_err(|_| AuditError::SessionLockPoisoned)?;
        let lock_file = lock_file.as_ref().ok_or(AuditError::ClaimNotActive)?;
        validate_held_lock(lock_file, &live_claim.lock_path, &live_claim.lock_identity)?;
        if database_file_identity(&live_claim.database_path)? != live_claim.database_identity {
            return Err(AuditError::StoreMismatch);
        }
        let root = live_claim.database_path.parent().ok_or_else(|| {
            AuditError::UnsafeStateDir(live_claim.database_path.display().to_string())
        })?;
        ensure_sqlite_sidecars_private(root)?;
        let connection = open_connection(&live_claim.database_path)?;
        if database_file_identity(&live_claim.database_path)? != live_claim.database_identity {
            return Err(AuditError::StoreMismatch);
        }
        ensure_sqlite_sidecars_private(root)?;
        let database_id: String = connection.query_row(
            "SELECT database_id FROM store_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if database_id != live_claim.database_id {
            return Err(AuditError::StoreMismatch);
        }
        verify_database(&connection)?;
        let row: Option<(String, String)> = connection
            .query_row(
                "SELECT a.binding_json,i.authority_json FROM authorizations a \
                 JOIN executions e ON e.execution_id=a.current_execution_id \
                 JOIN intents i ON i.execution_id=e.execution_id \
                 WHERE a.authorization_id=?1 AND a.state='claimed' \
                 AND a.current_execution_id=?2 AND a.current_fence_epoch=?3 \
                 AND e.state='active' AND e.authorization_id=?1 AND e.fence_epoch=?3 \
                 AND i.attempt_id=?4 AND i.authorization_id=?1 AND i.fence_epoch=?3 \
                 AND i.terminal_state='reserved'",
                params![
                    live_claim.authorization_id.as_str(),
                    live_claim.execution_id,
                    live_claim.fence_epoch as i64,
                    self.attempt_id.as_str(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((binding_json, authority_json)) = row else {
            return Err(AuditError::FenceEpochMismatch);
        };
        let binding: AuthorizationBinding =
            serde_json::from_str(&binding_json).map_err(AuditError::JournalDecode)?;
        let authority: IntentAuthority =
            serde_json::from_str(&authority_json).map_err(AuditError::JournalDecode)?;
        validate_binding(&binding)?;
        validate_authority_binding(&authority, &binding)?;
        validate_token_authority(self, &authority)
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
pub struct RecoveryRecord {
    pub batch_id: BatchId,
    pub authorization_id: AuthorizationId,
    pub action_id: ActionId,
    pub attempt_id: AttemptId,
    pub disposition: RecoveryDisposition,
    pub reason: String,
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

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Public API compatibility: Created transfers the opaque token by value.
pub enum IntentReservation {
    Created(DurableIntentToken),
    Existing(IntentReservationInfo),
    Conflicting(IntentReservationInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentReservationInfo {
    attempt_id: AttemptId,
    item_id: ItemId,
    action_id: ActionId,
    source_path_hash: PathHash,
    before_revalidation_digest: DigestString,
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
    fn matches_request(&self, request: &IntentRequest) -> bool {
        self.item_id == request.item_id
            && self.action_id == request.action_id
            && self.source_path_hash == request.source_path_hash
            && self.before_revalidation_digest == request.before_revalidation_digest
    }
}

#[derive(Debug, Clone)]
pub struct SimulatedOutcome {
    pub actual_platform_operation: String,
    pub adapter_version: String,
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
    pub stable_status: StableStatus,
    pub recovery_state: RecoveryState,
    pub source_postcheck: Observation,
    pub destination_postcheck: Option<Observation>,
    pub resulting_trash_locator: Option<String>,
    pub platform_result: Option<String>,
    pub platform_error_domain: Option<String>,
    pub platform_error_code: Option<String>,
    pub notes: Vec<String>,
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
        let located = destination_postcheck.exists
            || resulting_trash_locator
                .as_ref()
                .is_some_and(|value| !value.is_empty());
        let outcome = Self {
            actual_platform_operation: "simulated_trash".to_string(),
            adapter_version: adapter_version.into(),
            started_at,
            finished_at,
            stable_status: if located {
                StableStatus::TrashSucceededLocationReported
            } else {
                StableStatus::TrashSucceededPlatformReported
            },
            recovery_state: if located {
                RecoveryState::TrashLocationReported
            } else {
                RecoveryState::PlatformTrashReported
            },
            source_postcheck,
            destination_postcheck: Some(destination_postcheck),
            resulting_trash_locator,
            platform_result: Some(platform_result.into()),
            platform_error_domain: None,
            platform_error_code: None,
            notes,
        };
        validate_outcome_shape(RequestedMode::Trash, &outcome)?;
        Ok(outcome)
    }

    pub fn permanent_success(
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        source_postcheck: Observation,
        platform_result: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        let outcome = Self {
            actual_platform_operation: "simulated_permanent_delete".to_string(),
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
        };
        validate_outcome_shape(RequestedMode::Permanent, &outcome)?;
        Ok(outcome)
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
        Self::constructed(
            mode,
            adapter_version,
            started_at,
            finished_at,
            StableStatus::FailedSourceUnchanged,
            RecoveryState::FailedSourceUnchanged,
            Observation {
                exists: true,
                identity: Some(source_identity.into()),
            },
            Some(platform_result.into()),
            None,
            None,
            notes,
        )
    }

    pub fn cancelled_before_action(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        at: SystemTime,
        source_identity: impl Into<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::constructed(
            mode,
            adapter_version,
            at,
            at,
            StableStatus::CancelledBeforeAction,
            RecoveryState::CancelledBeforeAction,
            Observation {
                exists: true,
                identity: Some(source_identity.into()),
            },
            None,
            None,
            None,
            notes,
        )
    }

    pub fn vanished_before_action(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        at: SystemTime,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        Self::constructed(
            mode,
            adapter_version,
            at,
            at,
            StableStatus::VanishedBeforeAction,
            RecoveryState::VanishedBeforeAction,
            Observation {
                exists: false,
                identity: None,
            },
            None,
            None,
            None,
            notes,
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
        Self::constructed(
            mode,
            adapter_version,
            started_at,
            finished_at,
            StableStatus::IndeterminateAfterCrash,
            RecoveryState::Indeterminate,
            source_postcheck,
            None,
            None,
            None,
            notes,
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
        let recovery = if source_postcheck.exists {
            RecoveryState::FailedSourceUnchanged
        } else {
            RecoveryState::Indeterminate
        };
        Self::constructed(
            mode,
            adapter_version,
            started_at,
            finished_at,
            StableStatus::FailedPlatformError,
            recovery,
            source_postcheck,
            Some(platform_result.into()),
            Some(error_domain.into()),
            Some(error_code.into()),
            notes,
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
        let recovery = if source_postcheck.exists {
            RecoveryState::FailedSourceUnchanged
        } else {
            RecoveryState::Indeterminate
        };
        Self::constructed(
            mode,
            adapter_version,
            started_at,
            finished_at,
            StableStatus::FailedCancelledByPlatform,
            recovery,
            source_postcheck,
            Some(platform_result.into()),
            Some(error_domain.into()),
            Some(error_code.into()),
            notes,
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
        Self::constructed(
            mode,
            adapter_version,
            started_at,
            finished_at,
            StableStatus::IndeterminatePlatformResult,
            RecoveryState::Indeterminate,
            source_postcheck,
            None,
            None,
            None,
            notes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn constructed(
        mode: RequestedMode,
        adapter_version: impl Into<String>,
        started_at: SystemTime,
        finished_at: SystemTime,
        stable_status: StableStatus,
        recovery_state: RecoveryState,
        source_postcheck: Observation,
        platform_result: Option<String>,
        platform_error_domain: Option<String>,
        platform_error_code: Option<String>,
        notes: Vec<String>,
    ) -> Result<Self, AuditError> {
        let outcome = Self {
            actual_platform_operation: operation_for_mode(mode).to_string(),
            adapter_version: adapter_version.into(),
            started_at,
            finished_at,
            stable_status,
            recovery_state,
            source_postcheck,
            destination_postcheck: None,
            resulting_trash_locator: None,
            platform_result,
            platform_error_domain,
            platform_error_code,
            notes,
        };
        validate_outcome_shape(mode, &outcome)?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionCorruption {
    pub message: String,
}

impl fmt::Display for ProjectionCorruption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProjectionCorruption {}

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("audit projection corruption: {0}")]
    Corruption(#[from] ProjectionCorruption),
    #[error("audit projection unavailable: {0}")]
    Operational(#[from] AuditError),
}

#[derive(Debug)]
pub struct AuditStore {
    root: PathBuf,
    database_path: PathBuf,
    lock_path: PathBuf,
    database_id: String,
    lock_identity: LockIdentity,
    database_identity: FileIdentity,
    owner_pid: u32,
    coordinator: Arc<SessionCoordinator>,
}

impl Clone for AuditStore {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            database_path: self.database_path.clone(),
            lock_path: self.lock_path.clone(),
            database_id: self.database_id.clone(),
            lock_identity: self.lock_identity.clone(),
            database_identity: self.database_identity.clone(),
            owner_pid: self.owner_pid,
            coordinator: Arc::clone(&self.coordinator),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    canonical_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn database_file_identity(path: &Path) -> Result<FileIdentity, AuditError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        ensure_private_file_handle(&file, path)?;
        file_identity(&file)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(AuditError::UnsupportedPlatform)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentAuthority {
    attempt_id: AttemptId,
    nonce: NonceId,
    database_id: String,
    execution_id: String,
    authorization_id: AuthorizationId,
    authorization_source: AuthorizationSource,
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
    policy_version: String,
    policy_digest: DigestString,
    protected_anchor_snapshot_digest: DigestString,
    adapter_capabilities_digest: DigestString,
    cleaner_set_digest: DigestString,
    host_instance_id: HostId,
    user_identity: UserId,
    workflow_session: SessionId,
}

impl IntentAuthority {
    fn to_token(&self, live_claim: Weak<LiveClaimAuthority>) -> DurableIntentToken {
        DurableIntentToken {
            attempt_id: self.attempt_id.clone(),
            nonce: self.nonce.clone(),
            database_id: self.database_id.clone(),
            execution_id: self.execution_id.clone(),
            authorization_id: self.authorization_id.clone(),
            authorization_source: self.authorization_source,
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
            policy_version: self.policy_version.clone(),
            policy_digest: self.policy_digest.clone(),
            protected_anchor_snapshot_digest: self.protected_anchor_snapshot_digest.clone(),
            adapter_capabilities_digest: self.adapter_capabilities_digest.clone(),
            cleaner_set_digest: self.cleaner_set_digest.clone(),
            host_instance_id: self.host_instance_id.clone(),
            user_identity: self.user_identity.clone(),
            workflow_session: self.workflow_session.clone(),
            creator_pid: std::process::id(),
            live_claim,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeEvent {
    authority: IntentAuthority,
    actual_platform_operation: String,
    adapter_version: String,
    started_at_unix_ms: String,
    finished_at_unix_ms: String,
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
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum EventPayload {
    AuthorizationRegistered {
        binding: AuthorizationBinding,
    },
    ExecutionClaimed {
        authorization_id: AuthorizationId,
        execution_id: String,
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
        started_at_unix_ms: String,
    },
    RecoveryClaimed {
        authorization_id: AuthorizationId,
        previous_execution_id: String,
        execution_id: String,
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
        started_at_unix_ms: String,
    },
    ActionIntent {
        authority: IntentAuthority,
    },
    ActionOutcome {
        outcome: OutcomeEvent,
    },
    RecoveryOutcome {
        outcome: OutcomeEvent,
        #[serde(with = "decimal_u64")]
        recovery_fence_epoch: u64,
    },
    RecoveryClassification {
        authority: IntentAuthority,
        record: RecoveryRecord,
    },
    ExecutionConsumed {
        authorization_id: AuthorizationId,
        execution_id: String,
        #[serde(with = "decimal_u64")]
        fence_epoch: u64,
        ended_at_unix_ms: String,
    },
}

impl EventPayload {
    fn kind(&self) -> &'static str {
        match self {
            Self::AuthorizationRegistered { .. } => "authorization_registered",
            Self::ExecutionClaimed { .. } => "execution_claimed",
            Self::RecoveryClaimed { .. } => "recovery_claimed",
            Self::ActionIntent { .. } => "action_intent",
            Self::ActionOutcome { .. } => "action_outcome",
            Self::RecoveryOutcome { .. } => "recovery_outcome",
            Self::RecoveryClassification { .. } => "recovery_classification",
            Self::ExecutionConsumed { .. } => "execution_consumed",
        }
    }

    fn indexed_ids(&self) -> (Option<&str>, Option<&str>, Option<&str>) {
        match self {
            Self::AuthorizationRegistered { binding } => {
                (Some(binding.authorization_id.as_str()), None, None)
            }
            Self::ExecutionClaimed {
                authorization_id, ..
            }
            | Self::RecoveryClaimed {
                authorization_id, ..
            }
            | Self::ExecutionConsumed {
                authorization_id, ..
            } => (Some(authorization_id.as_str()), None, None),
            Self::ActionIntent { authority } => (
                Some(authority.authorization_id.as_str()),
                Some(authority.action_id.as_str()),
                Some(authority.attempt_id.as_str()),
            ),
            Self::ActionOutcome { outcome } => (
                Some(outcome.authority.authorization_id.as_str()),
                Some(outcome.authority.action_id.as_str()),
                Some(outcome.authority.attempt_id.as_str()),
            ),
            Self::RecoveryOutcome { outcome, .. } => (
                Some(outcome.authority.authorization_id.as_str()),
                Some(outcome.authority.action_id.as_str()),
                Some(outcome.authority.attempt_id.as_str()),
            ),
            Self::RecoveryClassification { authority, .. } => (
                Some(authority.authorization_id.as_str()),
                Some(authority.action_id.as_str()),
                Some(authority.attempt_id.as_str()),
            ),
        }
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit store is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("audit store filesystem is remote or has unsupported locality")]
    UnsupportedFilesystem,
    #[error("state directory must be absolute")]
    StateDirNotAbsolute,
    #[error("state directory {0} contains unsafe components")]
    UnsafeStateDir(String),
    #[error("state directory or file {0} must not be a symlink")]
    SymlinkRejected(String),
    #[error("state directory {0} is not private enough")]
    StateDirNotPrivate(String),
    #[error("state file {0} is not a private regular single-link file")]
    UnsafeStateFile(String),
    #[error("audit handles cannot be reused after process fork")]
    ForkedProcess,
    #[error("claimed execution mutation lock is poisoned")]
    SessionLockPoisoned,
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
    #[error("action is not authorized for the requested item")]
    ActionNotAuthorized,
    #[error("action {0} already has a reserved or completed attempt")]
    ActionAlreadyReserved(String),
    #[error("fence epoch mismatch")]
    FenceEpochMismatch,
    #[error("a later recovery claim is required for tokenless outcome recording")]
    RecoveryClaimRequired,
    #[error("fence epoch overflow")]
    FenceEpochOverflow,
    #[error("attempt {0} already exists")]
    AttemptAlreadyExists(String),
    #[error("an intent already exists for authorization/action {0}")]
    DuplicateActionIntent(String),
    #[error("attempt {0} has no durable matching intent")]
    IntentNotFound(String),
    #[error("outcome already exists for attempt {0}")]
    OutcomeAlreadyExists(String),
    #[error("unresolved intents remain")]
    UnresolvedIntentsRemain,
    #[error("tail truncation or durable head mismatch detected")]
    HeadMismatch,
    #[error("journal tampering detected at sequence {sequence}: {reason}")]
    JournalTampered { sequence: u64, reason: String },
    #[error("state file is too large")]
    StateTooLarge,
    #[error("journal file is too large")]
    JournalTooLarge,
    #[error("record exceeds bounded maximum size")]
    RecordTooLarge,
    #[error("database quota has been reached")]
    DatabaseTooLarge,
    #[error("successful outcome requires source absence")]
    SuccessRequiresSourceAbsent,
    #[error("trash success requires confirmed destination or trash locator evidence")]
    TrashSuccessRequiresDestinationEvidence,
    #[error("permanent success must not claim destination or trash locator")]
    PermanentSuccessMustNotClaimDestination,
    #[error("outcome fields are contradictory: {0}")]
    InvalidOutcome(&'static str),
    #[error("recovery observation is contradictory")]
    InvalidRecoveryObservation,
    #[error("invalid clock value")]
    InvalidClock,
    #[error("concurrent writer denied by exclusive store lock")]
    ConcurrentWriterDenied,
    #[error("claim belongs to a different audit store")]
    StoreMismatch,
    #[error("claim session is no longer active")]
    ClaimNotActive,
    #[error("audit lock file was replaced")]
    LockReplaced,
    #[error("SQLite integrity check failed: {0}")]
    IntegrityCheckFailed(String),
    #[error("SQLite schema or pragma mismatch: {0}")]
    DatabaseConfiguration(String),
    #[error("state file decode failed: {0}")]
    StateDecode(std::io::Error),
    #[error("head file decode failed: {0}")]
    HeadDecode(std::io::Error),
    #[error("journal decode failed: {0}")]
    JournalDecode(serde_json::Error),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
            let lock_path = root.join(LOCK_FILE);
            let lock_file = open_lock_file(&lock_path)?;
            ensure_local_filesystem(&lock_file)?;
            let lock_identity = lock_identity(&lock_file, &lock_path)?;
            let database_path = root.join(DATABASE_FILE);
            let database_preexisting = database_path.exists();
            if !database_preexisting {
                lock_file
                    .try_lock_exclusive()
                    .map_err(|_| AuditError::ConcurrentWriterDenied)?;
                create_private_database_file(&database_path)?;
            } else {
                lock_file
                    .try_lock_shared()
                    .map_err(|_| AuditError::ConcurrentWriterDenied)?;
            }
            ensure_sqlite_sidecars_private(&root)?;
            ensure_private_regular_file(&database_path)?;
            let mut connection = open_connection(&database_path)?;
            if database_preexisting {
                verify_initialized_database(&connection)?;
            } else {
                initialize_database(&mut connection)?;
            }
            ensure_sqlite_sidecars_private(&root)?;
            let database_id: String = connection.query_row(
                "SELECT database_id FROM store_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            validate_bounded_field(&database_id, "database_id", MAX_ID_BYTES)?;
            let database_file = OpenOptions::new().read(true).open(&database_path)?;
            ensure_same_local_filesystem(&lock_file, &database_file)?;
            let database_identity = file_identity(&database_file)?;
            FileExt::unlock(&lock_file)?;
            Ok(Self {
                root,
                database_path,
                lock_path,
                database_id,
                lock_identity,
                database_identity,
                owner_pid: std::process::id(),
                coordinator: Arc::new(SessionCoordinator {
                    active: AtomicBool::new(false),
                    mutation_lock: Mutex::new(()),
                }),
            })
        }
    }

    pub fn register_authorization(&self, request: RegisterAuthorization) -> Result<(), AuditError> {
        self.ensure_process()?;
        validate_binding(&request.binding)?;
        let binding_json = canonical_json(&request.binding)?;
        if binding_json.len() > MAX_BINDING_BYTES {
            return Err(AuditError::RecordTooLarge);
        }
        let _guard = self.short_lock()?;
        self.check_size_budget(false)?;
        let mut connection = self.connection_locked()?;
        verify_database(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 =
            transaction.query_row("SELECT count(*) FROM authorizations", [], |row| row.get(0))?;
        if count >= MAX_AUTHORIZATIONS {
            return Err(AuditError::StateTooLarge);
        }
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM authorizations WHERE authorization_id=?1)",
            [request.binding.authorization_id.as_str()],
            |row| row.get(0),
        )?;
        if exists {
            return Err(AuditError::AuthorizationAlreadyExists(
                request.binding.authorization_id.as_str().to_string(),
            ));
        }
        insert_authorization(&transaction, &request.binding, &binding_json)?;
        append_event(
            &transaction,
            &EventPayload::AuthorizationRegistered {
                binding: request.binding,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn claim_execution(
        &self,
        authorization_id: &AuthorizationId,
        expected_plan_digest: &DigestString,
    ) -> Result<ClaimedExecution, AuditError> {
        self.ensure_process()?;
        let _session_guard = self
            .coordinator
            .mutation_lock
            .lock()
            .map_err(|_| AuditError::SessionLockPoisoned)?;
        if self.coordinator.active.load(Ordering::Acquire) {
            return Err(AuditError::ConcurrentWriterDenied);
        }
        let lock_file = self.acquire_lifetime_lock()?;
        self.claim_session(lock_file, authorization_id, expected_plan_digest, false)
    }

    pub fn claim_recovery(
        &self,
        authorization_id: &AuthorizationId,
        expected_plan_digest: &DigestString,
    ) -> Result<ClaimedExecution, AuditError> {
        self.ensure_process()?;
        let _session_guard = self
            .coordinator
            .mutation_lock
            .lock()
            .map_err(|_| AuditError::SessionLockPoisoned)?;
        if self.coordinator.active.load(Ordering::Acquire) {
            return Err(AuditError::ConcurrentWriterDenied);
        }
        let lock_file = self.acquire_lifetime_lock()?;
        self.claim_session(lock_file, authorization_id, expected_plan_digest, true)
    }

    fn claim_session(
        &self,
        lock_file: File,
        authorization_id: &AuthorizationId,
        expected_plan_digest: &DigestString,
        recovery: bool,
    ) -> Result<ClaimedExecution, AuditError> {
        self.check_size_budget(false)?;
        let mut connection = self.connection_locked()?;
        verify_database(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (binding, state, current_fence, current_execution) =
            load_authorization(&transaction, authorization_id)?;
        if &binding.plan_digest != expected_plan_digest {
            return Err(AuditError::PlanDigestMismatch);
        }
        let latest_fence: i64 = transaction.query_row(
            "SELECT next_fence_epoch FROM store_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let next_fence = latest_fence
            .checked_add(1)
            .ok_or(AuditError::FenceEpochOverflow)?;
        let execution_id = random_id(&transaction, "execution")?;
        let now = unix_ms_i64(SystemTime::now())?;
        let payload = if recovery {
            if state == "unused" {
                return Err(AuditError::AuthorizationNotClaimed(
                    authorization_id.as_str().to_string(),
                ));
            }
            if state == "consumed" {
                return Err(AuditError::AuthorizationAlreadyConsumed(
                    authorization_id.as_str().to_string(),
                ));
            }
            let previous_execution = current_execution.ok_or(AuditError::HeadMismatch)?;
            let previous_fence = current_fence.ok_or(AuditError::HeadMismatch)?;
            let changed = transaction.execute(
                "UPDATE executions SET state='superseded', ended_at_ms=?1 WHERE execution_id=?2 AND fence_epoch=?3 AND state='active'",
                params![now, previous_execution, previous_fence],
            )?;
            if changed != 1 {
                return Err(AuditError::FenceEpochMismatch);
            }
            EventPayload::RecoveryClaimed {
                authorization_id: authorization_id.clone(),
                previous_execution_id: previous_execution,
                execution_id: execution_id.clone(),
                fence_epoch: next_fence as u64,
                started_at_unix_ms: now.to_string(),
            }
        } else {
            if state == "claimed" {
                return Err(AuditError::AuthorizationAlreadyClaimed(
                    authorization_id.as_str().to_string(),
                ));
            }
            if state == "consumed" {
                return Err(AuditError::AuthorizationAlreadyConsumed(
                    authorization_id.as_str().to_string(),
                ));
            }
            EventPayload::ExecutionClaimed {
                authorization_id: authorization_id.clone(),
                execution_id: execution_id.clone(),
                fence_epoch: next_fence as u64,
                started_at_unix_ms: now.to_string(),
            }
        };
        transaction.execute(
            "INSERT INTO executions(execution_id,authorization_id,fence_epoch,kind,state,started_at_ms) VALUES(?1,?2,?3,?4,'active',?5)",
            params![execution_id, authorization_id.as_str(), next_fence, if recovery { "recovery" } else { "execution" }, now],
        )?;
        let changed = transaction.execute(
            "UPDATE authorizations SET state='claimed',current_fence_epoch=?1,current_execution_id=?2 WHERE authorization_id=?3 AND state=?4",
            params![next_fence, execution_id, authorization_id.as_str(), if recovery { "claimed" } else { "unused" }],
        )?;
        if changed != 1 {
            return Err(AuditError::FenceEpochMismatch);
        }
        transaction.execute(
            "UPDATE store_meta SET next_fence_epoch=?1 WHERE singleton=1 AND next_fence_epoch=?2",
            params![next_fence, latest_fence],
        )?;
        append_event(&transaction, &payload)?;
        transaction.commit()?;
        let live_claim = Arc::new(LiveClaimAuthority {
            active: AtomicBool::new(true),
            coordinator: Arc::clone(&self.coordinator),
            lock_file: Mutex::new(Some(lock_file)),
            database_path: self.database_path.clone(),
            database_id: self.database_id.clone(),
            database_identity: self.database_identity.clone(),
            lock_path: self.lock_path.clone(),
            lock_identity: self.lock_identity.clone(),
            execution_id: execution_id.clone(),
            authorization_id: authorization_id.clone(),
            fence_epoch: next_fence as u64,
            owner_pid: std::process::id(),
        });
        self.coordinator.active.store(true, Ordering::Release);
        Ok(ClaimedExecution {
            binding,
            fence_epoch: next_fence as u64,
            database_id: self.database_id.clone(),
            execution_id,
            database_path: self.database_path.clone(),
            lock_identity: self.lock_identity.clone(),
            live_claim,
            _not_sync: std::marker::PhantomData,
        })
    }

    pub fn reserve_intent(
        &self,
        claimed: &ClaimedExecution,
        request: IntentRequest,
    ) -> Result<DurableIntentToken, AuditError> {
        match self.reserve_intent_once(claimed, request)? {
            IntentReservation::Created(token) => Ok(token),
            IntentReservation::Existing(info) | IntentReservation::Conflicting(info) => Err(
                AuditError::ActionAlreadyReserved(info.action_id.as_str().to_string()),
            ),
        }
    }

    pub fn reserve_intent_once(
        &self,
        claimed: &ClaimedExecution,
        request: IntentRequest,
    ) -> Result<IntentReservation, AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.validate_claim_guard(claimed)?;
        validate_intent_binding(&claimed.binding, &request)?;
        self.check_size_budget(false)?;
        let mut connection = self.connection()?;
        verify_database(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_live_claim(&transaction, claimed)?;
        let binding_json: String = transaction.query_row(
            "SELECT binding_json FROM authorizations WHERE authorization_id=?1",
            [claimed.authorization_id().as_str()],
            |row| row.get(0),
        )?;
        if binding_json != canonical_json(&claimed.binding)? {
            return Err(AuditError::AuthorizationBindingMismatch);
        }
        {
            let mut statement = transaction.prepare(
                "SELECT attempt_id,item_id,action_id,authority_json FROM intents WHERE authorization_id<>?1 AND terminal_state IN ('reserved','classified_indeterminate') ORDER BY ordinal",
            )?;
            let rows = statement.query_map([claimed.authorization_id().as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (attempt_id, item_id, action_id, authority_json) = row?;
                let authority: IntentAuthority =
                    serde_json::from_str(&authority_json).map_err(AuditError::JournalDecode)?;
                if authority.source_path_hash == request.source_path_hash {
                    return Ok(IntentReservation::Conflicting(IntentReservationInfo {
                        attempt_id: AttemptId::new(attempt_id)?,
                        item_id: ItemId::new(item_id)?,
                        action_id: ActionId::new(action_id)?,
                        source_path_hash: authority.source_path_hash.clone(),
                        before_revalidation_digest: authority.before_revalidation_digest.clone(),
                    }));
                }
            }
        }
        let existing: Option<(String, String, String, String)> = transaction.query_row(
            "SELECT attempt_id,item_id,action_id,authority_json FROM intents WHERE authorization_id=?1 AND action_id=?2",
            params![
                claimed.authorization_id().as_str(),
                request.action_id.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        if let Some((attempt_id, item_id, action_id, authority_json)) = existing {
            let authority: IntentAuthority =
                serde_json::from_str(&authority_json).map_err(AuditError::JournalDecode)?;
            let info = IntentReservationInfo {
                attempt_id: AttemptId::new(attempt_id)?,
                item_id: ItemId::new(item_id)?,
                action_id: ActionId::new(action_id)?,
                source_path_hash: authority.source_path_hash.clone(),
                before_revalidation_digest: authority.before_revalidation_digest.clone(),
            };
            return if info.matches_request(&request) {
                Ok(IntentReservation::Existing(info))
            } else {
                Ok(IntentReservation::Conflicting(info))
            };
        }
        let ordinal: i64 = transaction.query_row(
            "SELECT next_attempt_ordinal FROM store_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let next_ordinal = ordinal
            .checked_add(1)
            .ok_or(AuditError::FenceEpochOverflow)?;
        let attempt_id = AttemptId::new(random_id(&transaction, "attempt")?)?;
        let nonce = NonceId::new(random_id(&transaction, "nonce")?)?;
        let risk_tier = claimed
            .binding
            .risk_by_action
            .get(&request.action_id)
            .copied()
            .ok_or(AuditError::ActionNotAuthorized)?;
        let authority = IntentAuthority {
            attempt_id: attempt_id.clone(),
            nonce: nonce.clone(),
            database_id: self.database_id.clone(),
            execution_id: claimed.execution_id.clone(),
            authorization_id: claimed.binding.authorization_id.clone(),
            authorization_source: claimed.binding.authorization_source,
            batch_id: claimed.binding.batch_id.clone(),
            plan_id: claimed.binding.plan_id.clone(),
            plan_digest: claimed.binding.plan_digest.clone(),
            item_id: request.item_id,
            action_id: request.action_id,
            requested_mode: claimed.binding.requested_mode,
            risk_tier,
            source_path_hash: request.source_path_hash,
            before_revalidation_digest: request.before_revalidation_digest,
            fence_epoch: claimed.fence_epoch,
            policy_version: claimed.binding.policy_version.clone(),
            policy_digest: claimed.binding.policy_digest.clone(),
            protected_anchor_snapshot_digest: claimed
                .binding
                .protected_anchor_snapshot_digest
                .clone(),
            adapter_capabilities_digest: claimed.binding.adapter_capabilities_digest.clone(),
            cleaner_set_digest: claimed.binding.cleaner_set_digest.clone(),
            host_instance_id: claimed.binding.host_instance_id.clone(),
            user_identity: claimed.binding.user_identity.clone(),
            workflow_session: claimed.binding.workflow_session.clone(),
        };
        let authority_json = canonical_json(&authority)?;
        if authority_json.len() > MAX_RECORD_BYTES {
            return Err(AuditError::RecordTooLarge);
        }
        transaction.execute(
            "INSERT INTO intents(attempt_id,ordinal,nonce,authorization_id,execution_id,fence_epoch,item_id,action_id,source_path_hash,before_revalidation_digest,authority_json,terminal_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'reserved')",
            params![attempt_id.as_str(), next_ordinal, nonce.as_str(), authority.authorization_id.as_str(), authority.execution_id, authority.fence_epoch as i64, authority.item_id.as_str(), authority.action_id.as_str(), authority.source_path_hash.as_str(), authority.before_revalidation_digest.as_str(), authority_json],
        )?;
        transaction.execute("UPDATE store_meta SET next_attempt_ordinal=?1 WHERE singleton=1 AND next_attempt_ordinal=?2", params![next_ordinal, ordinal])?;
        append_event(
            &transaction,
            &EventPayload::ActionIntent {
                authority: authority.clone(),
            },
        )?;
        transaction.commit()?;
        Ok(IntentReservation::Created(
            authority.to_token(Arc::downgrade(&claimed.live_claim)),
        ))
    }

    pub fn record_outcome(
        &self,
        claimed: &ClaimedExecution,
        token: &DurableIntentToken,
        outcome: SimulatedOutcome,
    ) -> Result<(), AuditError> {
        ensure_claim_matches_token(claimed, token)?;
        token.validate_current_process()?;
        let _mutation_guard = claimed.lock_mutation()?;
        self.validate_claim_guard(claimed)?;
        let validated = validate_outcome(token, outcome)?;
        self.check_size_budget(true)?;
        let mut connection = self.connection()?;
        verify_database(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_live_claim(&transaction, claimed)?;
        let (authority, terminal_state) = load_intent(&transaction, token.attempt_id())?;
        validate_token_authority(token, &authority)?;
        if terminal_state != "reserved" {
            return Err(AuditError::OutcomeAlreadyExists(
                token.attempt_id().as_str().to_string(),
            ));
        }
        let event = outcome_event(authority.clone(), validated);
        let outcome_json = canonical_json(&event)?;
        if outcome_json.len() > MAX_RECORD_BYTES {
            return Err(AuditError::RecordTooLarge);
        }
        transaction.execute(
            "INSERT INTO outcomes(attempt_id,outcome_json) VALUES(?1,?2)",
            params![token.attempt_id().as_str(), outcome_json],
        )?;
        let changed = transaction.execute("UPDATE intents SET terminal_state='outcome_recorded' WHERE attempt_id=?1 AND terminal_state='reserved'", [token.attempt_id().as_str()])?;
        if changed != 1 {
            return Err(AuditError::OutcomeAlreadyExists(
                token.attempt_id().as_str().to_string(),
            ));
        }
        append_event(
            &transaction,
            &EventPayload::ActionOutcome { outcome: event },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_recovery_outcome(
        &self,
        claimed: &ClaimedExecution,
        attempt_id: &AttemptId,
        outcome: SimulatedOutcome,
    ) -> Result<(), AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.validate_claim_guard(claimed)?;
        self.check_size_budget(true)?;
        let mut connection = self.connection()?;
        verify_database(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_live_claim(&transaction, claimed)?;
        let (authority, terminal_state) = load_intent(&transaction, attempt_id)?;
        if authority.authorization_id != claimed.binding.authorization_id
            || authority.batch_id != claimed.binding.batch_id
            || claimed.binding.item_by_action.get(&authority.action_id) != Some(&authority.item_id)
            || claimed.fence_epoch <= authority.fence_epoch
        {
            return Err(AuditError::RecoveryClaimRequired);
        }
        if terminal_state == "outcome_recorded" {
            return Err(AuditError::OutcomeAlreadyExists(
                attempt_id.as_str().to_string(),
            ));
        }
        let validated = validate_outcome_for_mode(authority.requested_mode, outcome)?;
        let event = outcome_event(authority, validated);
        let outcome_json = canonical_json(&event)?;
        if outcome_json.len() > MAX_RECORD_BYTES {
            return Err(AuditError::RecordTooLarge);
        }
        transaction.execute(
            "INSERT OR REPLACE INTO outcomes(attempt_id,outcome_json) VALUES(?1,?2)",
            params![attempt_id.as_str(), outcome_json],
        )?;
        transaction.execute(
            "DELETE FROM recoveries WHERE attempt_id=?1",
            [attempt_id.as_str()],
        )?;
        let changed = transaction.execute(
            "UPDATE intents SET terminal_state='outcome_recorded' WHERE attempt_id=?1 AND terminal_state<>'outcome_recorded'",
            [attempt_id.as_str()],
        )?;
        if changed != 1 {
            return Err(AuditError::OutcomeAlreadyExists(
                attempt_id.as_str().to_string(),
            ));
        }
        append_event(
            &transaction,
            &EventPayload::RecoveryOutcome {
                outcome: event,
                recovery_fence_epoch: claimed.fence_epoch,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn unresolved_recovery_intents(
        &self,
        claimed: &ClaimedExecution,
    ) -> Result<Vec<IntentReservationInfo>, AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.validate_claim_guard(claimed)?;
        let connection = self.connection()?;
        verify_database(&connection)?;
        validate_live_claim_connection(&connection, claimed)?;
        let mut statement = connection.prepare(
            "SELECT attempt_id,item_id,action_id,source_path_hash,before_revalidation_digest FROM intents WHERE authorization_id=?1 AND terminal_state<>'outcome_recorded' ORDER BY ordinal",
        )?;
        let rows = statement.query_map([claimed.authorization_id().as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (attempt, item, action, source_path_hash, before_revalidation_digest) = row?;
            Ok(IntentReservationInfo {
                attempt_id: AttemptId::new(attempt)?,
                item_id: ItemId::new(item)?,
                action_id: ActionId::new(action)?,
                source_path_hash: PathHash::new(source_path_hash)?,
                before_revalidation_digest: DigestString::new(before_revalidation_digest)?,
            })
        })
        .collect()
    }

    pub fn classify_recovery(
        &self,
        claimed: &ClaimedExecution,
        observer: &dyn RecoveryObserver,
    ) -> Result<Vec<RecoveryRecord>, AuditError> {
        let (reserved, mut existing) = {
            let _mutation_guard = claimed.lock_mutation()?;
            self.validate_claim_guard(claimed)?;
            let connection = self.connection()?;
            verify_database(&connection)?;
            validate_live_claim_connection(&connection, claimed)?;
            load_recovery_candidates(&connection, claimed.authorization_id())?
        };
        let mut pending = Vec::new();
        for authority in reserved {
            let view = RecoveryIntentView {
                info: IntentReservationInfo {
                    attempt_id: authority.attempt_id.clone(),
                    item_id: authority.item_id.clone(),
                    action_id: authority.action_id.clone(),
                    source_path_hash: authority.source_path_hash.clone(),
                    before_revalidation_digest: authority.before_revalidation_digest.clone(),
                },
                authorization_source: authority.authorization_source,
            };
            let observation = observer.observe(&view)?;
            let (disposition, reason) =
                classify_observation(authority.requested_mode, &observation)?;
            pending.push((authority, observation, disposition, reason));
        }
        if pending.is_empty() {
            return Ok(existing);
        }
        let _mutation_guard = claimed.lock_mutation()?;
        self.validate_claim_guard(claimed)?;
        self.check_size_budget(true)?;
        let mut connection = self.connection()?;
        verify_database(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_live_claim(&transaction, claimed)?;
        for (authority, _observation, disposition, reason) in pending {
            let (_, state) = load_intent(&transaction, &authority.attempt_id)?;
            if state != "reserved" {
                return Err(AuditError::OutcomeAlreadyExists(
                    authority.attempt_id.as_str().to_string(),
                ));
            }
            let record = RecoveryRecord {
                batch_id: authority.batch_id.clone(),
                authorization_id: authority.authorization_id.clone(),
                action_id: authority.action_id.clone(),
                attempt_id: authority.attempt_id.clone(),
                disposition,
                reason,
            };
            let record_json = canonical_json(&record)?;
            transaction.execute(
                "INSERT INTO recoveries(attempt_id,disposition,record_json) VALUES(?1,?2,?3)",
                params![
                    authority.attempt_id.as_str(),
                    disposition_db(disposition),
                    record_json
                ],
            )?;
            let changed = transaction.execute("UPDATE intents SET terminal_state=?1 WHERE attempt_id=?2 AND terminal_state='reserved'", params![terminal_for_disposition(disposition), authority.attempt_id.as_str()])?;
            if changed != 1 {
                return Err(AuditError::OutcomeAlreadyExists(
                    authority.attempt_id.as_str().to_string(),
                ));
            }
            append_event(
                &transaction,
                &EventPayload::RecoveryClassification {
                    authority,
                    record: record.clone(),
                },
            )?;
            existing.push(record);
        }
        transaction.commit()?;
        existing.sort_by(|left, right| left.attempt_id.cmp(&right.attempt_id));
        Ok(existing)
    }

    pub fn consume_execution(&self, claimed: &ClaimedExecution) -> Result<(), AuditError> {
        let _mutation_guard = claimed.lock_mutation()?;
        self.validate_claim_guard(claimed)?;
        self.check_size_budget(true)?;
        let mut connection = self.connection()?;
        verify_database(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<(String, Option<i64>, Option<String>)> = transaction.query_row(
            "SELECT state,current_fence_epoch,current_execution_id FROM authorizations WHERE authorization_id=?1",
            [claimed.authorization_id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let Some((state, fence, execution)) = state else {
            return Err(AuditError::AuthorizationUnknown(
                claimed.authorization_id().as_str().to_string(),
            ));
        };
        if state == "consumed" && fence == Some(claimed.fence_epoch as i64) {
            release_live_claim(&claimed.live_claim);
            return Ok(());
        }
        if state != "claimed"
            || fence != Some(claimed.fence_epoch as i64)
            || execution.as_deref() != Some(&claimed.execution_id)
        {
            return Err(AuditError::FenceEpochMismatch);
        }
        let unresolved: i64 = transaction.query_row(
            "SELECT count(*) FROM intents WHERE authorization_id=?1 AND terminal_state<>'outcome_recorded'",
            [claimed.authorization_id().as_str()], |row| row.get(0),
        )?;
        if unresolved != 0 {
            return Err(AuditError::UnresolvedIntentsRemain);
        }
        let changed = transaction.execute(
            "UPDATE authorizations SET state='consumed',current_execution_id=NULL WHERE authorization_id=?1 AND state='claimed' AND current_execution_id=?2 AND current_fence_epoch=?3",
            params![claimed.authorization_id().as_str(), claimed.execution_id, claimed.fence_epoch as i64],
        )?;
        if changed != 1 {
            return Err(AuditError::FenceEpochMismatch);
        }
        let now = unix_ms_i64(SystemTime::now())?;
        transaction.execute("UPDATE executions SET state='consumed',ended_at_ms=?1 WHERE execution_id=?2 AND state='active'", params![now, claimed.execution_id])?;
        append_event(
            &transaction,
            &EventPayload::ExecutionConsumed {
                authorization_id: claimed.authorization_id().clone(),
                execution_id: claimed.execution_id.clone(),
                fence_epoch: claimed.fence_epoch,
                ended_at_unix_ms: now.to_string(),
            },
        )?;
        transaction.commit()?;
        release_live_claim(&claimed.live_claim);
        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<IntegritySummary, AuditError> {
        self.ensure_process()?;
        if self.coordinator.active.load(Ordering::Acquire) {
            let _mutation_guard = self
                .coordinator
                .mutation_lock
                .lock()
                .map_err(|_| AuditError::SessionLockPoisoned)?;
            if self.coordinator.active.load(Ordering::Acquire) {
                return self.integrity_summary_locked();
            }
        }
        let _guard = self.short_lock()?;
        self.integrity_summary_locked()
    }

    pub fn projection_snapshot(&self) -> Result<AuditProjectionSnapshot, ProjectionError> {
        self.projection_snapshot_result()
            .map_err(|error| match error {
                AuditError::HeadMismatch
                | AuditError::JournalTampered { .. }
                | AuditError::IntegrityCheckFailed(_)
                | AuditError::DatabaseConfiguration(_)
                | AuditError::JournalDecode(_) => {
                    ProjectionError::Corruption(ProjectionCorruption {
                        message: format!("audit projection unavailable: {error}"),
                    })
                }
                other => ProjectionError::Operational(other),
            })
    }

    fn projection_snapshot_result(&self) -> Result<AuditProjectionSnapshot, AuditError> {
        self.ensure_process()?;
        if self.coordinator.active.load(Ordering::Acquire) {
            let _mutation_guard = self
                .coordinator
                .mutation_lock
                .lock()
                .map_err(|_| AuditError::SessionLockPoisoned)?;
            if self.coordinator.active.load(Ordering::Acquire) {
                return self.projection_snapshot_locked();
            }
        }
        let _guard = self.short_lock()?;
        self.projection_snapshot_locked()
    }

    fn projection_snapshot_locked(&self) -> Result<AuditProjectionSnapshot, AuditError> {
        let connection = self.connection_locked()?;
        let replayed = replay_projection(&connection)?;
        verify_replayed_projection(&connection, &replayed)?;
        self.check_size_budget(true)?;
        projection_snapshot_from_replay(&replayed)
    }

    fn integrity_summary_locked(&self) -> Result<IntegritySummary, AuditError> {
        let connection = self.connection_locked()?;
        let summary = verify_database(&connection)?;
        self.check_size_budget(true)?;
        Ok(summary)
    }

    fn connection(&self) -> Result<Connection, AuditError> {
        self.ensure_process()?;
        // Claimed operations already retain the exclusive lifetime lock.
        self.connection_locked()
    }

    fn connection_locked(&self) -> Result<Connection, AuditError> {
        ensure_private_state_dir(&self.root)?;
        ensure_private_regular_file(&self.database_path)?;
        let database_file = OpenOptions::new().read(true).open(&self.database_path)?;
        if file_identity(&database_file)? != self.database_identity {
            return Err(AuditError::StoreMismatch);
        }
        ensure_local_filesystem(&database_file)?;
        ensure_sqlite_sidecars_private(&self.root)?;
        let connection = open_connection(&self.database_path)?;
        ensure_private_regular_file(&self.database_path)?;
        let reopened_database = OpenOptions::new().read(true).open(&self.database_path)?;
        if file_identity(&reopened_database)? != self.database_identity {
            return Err(AuditError::StoreMismatch);
        }
        ensure_same_local_filesystem(&database_file, &reopened_database)?;
        ensure_sqlite_sidecars_private(&self.root)?;
        let database_id: String = connection.query_row(
            "SELECT database_id FROM store_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if database_id != self.database_id {
            return Err(AuditError::StoreMismatch);
        }
        Ok(connection)
    }

    fn short_lock(&self) -> Result<ShortStoreLock, AuditError> {
        self.ensure_process()?;
        let file = open_lock_file(&self.lock_path)?;
        if lock_identity(&file, &self.lock_path)? != self.lock_identity {
            return Err(AuditError::LockReplaced);
        }
        file.try_lock_exclusive()
            .map_err(|_| AuditError::ConcurrentWriterDenied)?;
        self.validate_lock_path_identity(&file)?;
        ensure_same_local_filesystem(
            &file,
            &OpenOptions::new().read(true).open(&self.database_path)?,
        )?;
        ensure_sqlite_sidecars_private(&self.root)?;
        Ok(ShortStoreLock { file })
    }

    fn acquire_lifetime_lock(&self) -> Result<File, AuditError> {
        self.ensure_process()?;
        let file = open_lock_file(&self.lock_path)?;
        if lock_identity(&file, &self.lock_path)? != self.lock_identity {
            return Err(AuditError::LockReplaced);
        }
        file.try_lock_exclusive()
            .map_err(|_| AuditError::ConcurrentWriterDenied)?;
        self.validate_lock_path_identity(&file)?;
        ensure_same_local_filesystem(
            &file,
            &OpenOptions::new().read(true).open(&self.database_path)?,
        )?;
        ensure_sqlite_sidecars_private(&self.root)?;
        Ok(file)
    }

    fn validate_claim_guard(&self, claimed: &ClaimedExecution) -> Result<(), AuditError> {
        claimed.validate_current_process()?;
        if !claimed.live_claim.active.load(Ordering::Acquire) {
            return Err(AuditError::ClaimNotActive);
        }
        if claimed.database_id != self.database_id || claimed.database_path != self.database_path {
            return Err(AuditError::AuthorizationBindingMismatch);
        }
        if claimed.lock_identity != self.lock_identity {
            return Err(AuditError::LockReplaced);
        }
        let lock_file = claimed
            .live_claim
            .lock_file
            .lock()
            .map_err(|_| AuditError::SessionLockPoisoned)?;
        let lock_file = lock_file.as_ref().ok_or(AuditError::ClaimNotActive)?;
        validate_held_lock(lock_file, &self.lock_path, &self.lock_identity)?;
        ensure_same_local_filesystem(
            lock_file,
            &OpenOptions::new().read(true).open(&self.database_path)?,
        )?;
        ensure_sqlite_sidecars_private(&self.root)?;
        Ok(())
    }

    fn validate_lock_path_identity(&self, held_file: &File) -> Result<(), AuditError> {
        let held = lock_identity(held_file, &self.lock_path)?;
        let current = open_existing_lock_file(&self.lock_path)?;
        let current_identity = lock_identity(&current, &self.lock_path)?;
        if held != self.lock_identity || current_identity != self.lock_identity {
            return Err(AuditError::LockReplaced);
        }
        Ok(())
    }

    fn ensure_process(&self) -> Result<(), AuditError> {
        if self.owner_pid == std::process::id() {
            Ok(())
        } else {
            Err(AuditError::ForkedProcess)
        }
    }

    fn check_size_budget(&self, allow_emergency: bool) -> Result<(), AuditError> {
        let db = file_len_if_exists(&self.database_path)?;
        let wal = file_len_if_exists(&self.root.join(format!("{DATABASE_FILE}-wal")))?;
        let shm = file_len_if_exists(&self.root.join(format!("{DATABASE_FILE}-shm")))?;
        if db > MAX_DATABASE_BYTES
            || wal > MAX_WAL_BYTES
            || db.saturating_add(wal).saturating_add(shm) > MAX_TOTAL_DATABASE_BYTES
        {
            return Err(AuditError::DatabaseTooLarge);
        }
        if !allow_emergency
            && db.saturating_add(wal).saturating_add(shm)
                > MAX_TOTAL_DATABASE_BYTES - 8 * 1024 * 1024
        {
            return Err(AuditError::DatabaseTooLarge);
        }
        Ok(())
    }
}

struct ShortStoreLock {
    file: File,
}
impl Drop for ShortStoreLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

const SCHEMA_SQL: &str = r#"
CREATE TABLE store_meta(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version TEXT NOT NULL,
  database_id TEXT NOT NULL,
  next_fence_epoch INTEGER NOT NULL CHECK(next_fence_epoch>=0),
  next_attempt_ordinal INTEGER NOT NULL CHECK(next_attempt_ordinal>=0)
) STRICT;
CREATE TABLE audit_head(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  sequence INTEGER NOT NULL CHECK(sequence>=0),
  digest TEXT
) STRICT;
CREATE TABLE authorizations(
  authorization_id TEXT PRIMARY KEY,
  plan_digest TEXT NOT NULL,
  binding_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('unused','claimed','consumed')),
  current_fence_epoch INTEGER,
  current_execution_id TEXT
) STRICT;
CREATE TABLE authorization_items(
  authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id),
  item_id TEXT NOT NULL,
  PRIMARY KEY(authorization_id,item_id)
) STRICT;
CREATE TABLE authorization_actions(
  authorization_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  risk TEXT NOT NULL CHECK(risk IN ('r1','r2','r3','r4')),
  PRIMARY KEY(authorization_id,action_id),
  FOREIGN KEY(authorization_id,item_id) REFERENCES authorization_items(authorization_id,item_id)
) STRICT;
CREATE TABLE executions(
  execution_id TEXT PRIMARY KEY,
  authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id),
  fence_epoch INTEGER NOT NULL UNIQUE CHECK(fence_epoch>0),
  kind TEXT NOT NULL CHECK(kind IN ('execution','recovery')),
  state TEXT NOT NULL CHECK(state IN ('active','superseded','consumed')),
  started_at_ms INTEGER NOT NULL CHECK(started_at_ms>=0),
  ended_at_ms INTEGER
) STRICT;
CREATE TABLE intents(
  attempt_id TEXT PRIMARY KEY,
  ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>0),
  nonce TEXT NOT NULL UNIQUE,
  authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id),
  execution_id TEXT NOT NULL REFERENCES executions(execution_id),
  fence_epoch INTEGER NOT NULL,
  item_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  source_path_hash TEXT NOT NULL,
  before_revalidation_digest TEXT NOT NULL,
  authority_json TEXT NOT NULL,
  terminal_state TEXT NOT NULL CHECK(terminal_state IN ('reserved','outcome_recorded','classified_pending','classified_reserved','classified_indeterminate')),
  UNIQUE(authorization_id,action_id),
  FOREIGN KEY(authorization_id,action_id) REFERENCES authorization_actions(authorization_id,action_id)
) STRICT;
CREATE TABLE outcomes(
  attempt_id TEXT PRIMARY KEY REFERENCES intents(attempt_id),
  outcome_json TEXT NOT NULL
) STRICT;
CREATE TABLE recoveries(
  attempt_id TEXT PRIMARY KEY REFERENCES intents(attempt_id),
  disposition TEXT NOT NULL CHECK(disposition IN ('pending','reserved','indeterminate')),
  record_json TEXT NOT NULL
) STRICT;
CREATE TABLE audit_events(
  sequence INTEGER PRIMARY KEY CHECK(sequence>0),
  recorded_at_ms INTEGER NOT NULL CHECK(recorded_at_ms>=0),
  monotonic_elapsed_ns TEXT NOT NULL,
  kind TEXT NOT NULL,
  authorization_id TEXT,
  action_id TEXT,
  attempt_id TEXT,
  previous_digest TEXT,
  payload_json TEXT NOT NULL,
  digest TEXT NOT NULL
) STRICT;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'audit events are append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'audit events are append-only'); END;
"#;

fn ensure_private_state_dir(root: &Path) -> Result<(), AuditError> {
    if !root.is_absolute() {
        return Err(AuditError::StateDirNotAbsolute);
    }
    let mut saw_root = false;
    for component in root.components() {
        match component {
            Component::Prefix(_) if !saw_root => {}
            Component::RootDir if !saw_root => saw_root = true,
            Component::Normal(_) if saw_root => {}
            _ => return Err(AuditError::UnsafeStateDir(root.display().to_string())),
        }
    }
    if !saw_root {
        return Err(AuditError::StateDirNotAbsolute);
    }
    ensure_existing_ancestors_not_symlinks(root)?;
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(AuditError::SymlinkRejected(root.display().to_string()));
            }
            if !metadata.is_dir() {
                return Err(AuditError::UnsafeStateDir(root.display().to_string()));
            }
            validate_private_directory_metadata(root, &metadata)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).recursive(false).create(root)?;
            }
            #[cfg(not(unix))]
            fs::create_dir(root)?;
            let metadata = fs::symlink_metadata(root)?;
            validate_private_directory_metadata(root, &metadata)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn ensure_existing_ancestors_not_symlinks(path: &Path) -> Result<(), AuditError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AuditError::SymlinkRejected(current.display().to_string()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_private_directory_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AuditError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(AuditError::StateDirNotPrivate(path.display().to_string()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_local_filesystem(file: &File) -> Result<(), AuditError> {
    use std::os::fd::AsRawFd;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `file` owns a valid descriptor and `stat` points to writable storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful statfs initialized the structure.
    let filesystem_type = unsafe { stat.assume_init() }.f_type as u32;
    const KNOWN_LOCAL: &[u32] = &[
        0x0000_ef53, // ext2/3/4
        0x5846_5342, // XFS
        0x9123_683e, // Btrfs
        0xf2f5_2010, // F2FS
    ];
    if KNOWN_LOCAL.contains(&filesystem_type) {
        Ok(())
    } else {
        Err(AuditError::UnsupportedFilesystem)
    }
}

#[cfg(target_os = "macos")]
fn ensure_local_filesystem(file: &File) -> Result<(), AuditError> {
    use std::os::fd::AsRawFd;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `file` owns a valid descriptor and `stat` points to writable storage.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful statfs initialized the structure.
    let stat = unsafe { stat.assume_init() };
    let bytes = stat
        .f_fstypename
        .iter()
        .map(|value| *value as u8)
        .take_while(|value| *value != 0)
        .collect::<Vec<_>>();
    if stat.f_flags & libc::MNT_LOCAL as u32 != 0
        && stat.f_flags & libc::MNT_IGNORE_OWNERSHIP as u32 == 0
        && bytes == b"apfs"
    {
        Ok(())
    } else {
        Err(AuditError::UnsupportedFilesystem)
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn ensure_local_filesystem(_file: &File) -> Result<(), AuditError> {
    Err(AuditError::UnsupportedPlatform)
}

fn ensure_same_local_filesystem(first: &File, second: &File) -> Result<(), AuditError> {
    ensure_local_filesystem(first)?;
    ensure_local_filesystem(second)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if first.metadata()?.dev() != second.metadata()?.dev() {
            return Err(AuditError::UnsupportedFilesystem);
        }
    }
    Ok(())
}

fn open_lock_file(path: &Path) -> Result<File, AuditError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(AuditError::SymlinkRejected(path.display().to_string()));
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    ensure_private_file_handle(&file, path)?;
    Ok(file)
}

fn open_existing_lock_file(path: &Path) -> Result<File, AuditError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(AuditError::SymlinkRejected(path.display().to_string()));
    }
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    ensure_private_file_handle(&file, path)?;
    Ok(file)
}

fn validate_held_lock(
    held_file: &File,
    path: &Path,
    expected: &LockIdentity,
) -> Result<(), AuditError> {
    let probe = open_existing_lock_file(path)?;
    if lock_identity(held_file, path)? != *expected || lock_identity(&probe, path)? != *expected {
        return Err(AuditError::LockReplaced);
    }
    match probe.try_lock_exclusive() {
        Ok(()) => {
            let _ = FileExt::unlock(&probe);
            Err(AuditError::ClaimNotActive)
        }
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_private_database_file(path: &Path) -> Result<(), AuditError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?
            .sync_all()?;
    }
    #[cfg(not(unix))]
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?
        .sync_all()?;
    sync_directory(
        path.parent()
            .ok_or_else(|| AuditError::UnsafeStateDir(path.display().to_string()))?,
    )
}

fn ensure_private_regular_file(path: &Path) -> Result<(), AuditError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(AuditError::SymlinkRejected(path.display().to_string()));
    }
    let file = OpenOptions::new().read(true).open(path)?;
    ensure_private_file_handle(&file, path)
}

fn ensure_private_file_handle(file: &File, path: &Path) -> Result<(), AuditError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AuditError::UnsafeStateFile(path.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(AuditError::UnsafeStateFile(path.display().to_string()));
        }
    }
    Ok(())
}

fn lock_identity(file: &File, _path: &Path) -> Result<LockIdentity, AuditError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(LockIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(LockIdentity {
            canonical_path: fs::canonicalize(_path)?,
        })
    }
}

fn file_identity(file: &File) -> Result<FileIdentity, AuditError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(AuditError::UnsupportedPlatform)
    }
}

fn ensure_sqlite_sidecars_private(root: &Path) -> Result<(), AuditError> {
    for name in [
        format!("{DATABASE_FILE}-wal"),
        format!("{DATABASE_FILE}-shm"),
    ] {
        let path = root.join(name);
        if path.exists() {
            ensure_private_regular_file(&path)?;
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), AuditError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    Ok(())
}

fn open_connection(path: &Path) -> Result<Connection, AuditError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    connection.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA mmap_size=0; PRAGMA trusted_schema=OFF; PRAGMA read_uncommitted=OFF; PRAGMA locking_mode=NORMAL; PRAGMA temp_store=MEMORY; PRAGMA wal_autocheckpoint=64; PRAGMA journal_size_limit=16777216;",
    )?;
    let journal: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(AuditError::DatabaseConfiguration(
            "journal_mode is not WAL".to_string(),
        ));
    }
    verify_connection_pragmas(&connection)?;
    Ok(connection)
}

fn verify_connection_pragmas(connection: &Connection) -> Result<(), AuditError> {
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let mmap_size: i64 = connection.pragma_query_value(None, "mmap_size", |row| row.get(0))?;
    let trusted: i64 = connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.pragma_query_value(None, "read_uncommitted", |row| row.get(0))?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if foreign_keys != 1
        || synchronous != 2
        || mmap_size != 0
        || trusted != 0
        || read_uncommitted != 0
        || !journal.eq_ignore_ascii_case("wal")
        || !connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?
        || connection.db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)?
    {
        return Err(AuditError::DatabaseConfiguration(
            "required SQLite safety settings are not active".to_string(),
        ));
    }
    Ok(())
}

fn initialize_database(connection: &mut Connection) -> Result<(), AuditError> {
    connection.pragma_update(None, "page_size", PAGE_SIZE as i64)?;
    connection.pragma_update(None, "max_page_count", MAX_PAGE_COUNT as i64)?;
    connection.pragma_update(None, "application_id", APPLICATION_ID)?;
    connection.pragma_update(None, "user_version", USER_VERSION)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_SQL)?;
    let database_id = random_id(&transaction, "database")?;
    transaction.execute(
        "INSERT INTO store_meta VALUES(1,?1,?2,0,0)",
        params![SCHEMA_VERSION, database_id],
    )?;
    transaction.execute("INSERT INTO audit_head VALUES(1,0,NULL)", [])?;
    transaction.commit()?;
    verify_initialized_database(connection)?;
    sync_directory(
        connection
            .path()
            .and_then(|path| Path::new(path).parent())
            .ok_or_else(|| {
                AuditError::DatabaseConfiguration("database path unavailable".to_string())
            })?,
    )
}

fn verify_initialized_database(connection: &Connection) -> Result<(), AuditError> {
    let app_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let mut max_pages: i64 =
        connection.pragma_query_value(None, "max_page_count", |row| row.get(0))?;
    if max_pages > MAX_PAGE_COUNT as i64 {
        connection.pragma_update(None, "max_page_count", MAX_PAGE_COUNT as i64)?;
        max_pages = connection.pragma_query_value(None, "max_page_count", |row| row.get(0))?;
    }
    if app_id != APPLICATION_ID
        || user_version != USER_VERSION
        || page_size != PAGE_SIZE as i64
        || max_pages != MAX_PAGE_COUNT as i64
    {
        return Err(AuditError::DatabaseConfiguration(
            "database header values do not match the audit schema".to_string(),
        ));
    }
    let schema: String = connection.query_row(
        "SELECT schema_version FROM store_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if schema != SCHEMA_VERSION {
        return Err(AuditError::DatabaseConfiguration(
            "unsupported audit schema".to_string(),
        ));
    }
    Ok(())
}

fn insert_authorization(
    transaction: &Transaction<'_>,
    binding: &AuthorizationBinding,
    binding_json: &str,
) -> Result<(), AuditError> {
    transaction.execute(
        "INSERT INTO authorizations(authorization_id,plan_digest,binding_json,state) VALUES(?1,?2,?3,'unused')",
        params![binding.authorization_id.as_str(), binding.plan_digest.as_str(), binding_json],
    )?;
    for item_id in &binding.item_ids {
        transaction.execute(
            "INSERT INTO authorization_items VALUES(?1,?2)",
            params![binding.authorization_id.as_str(), item_id.as_str()],
        )?;
    }
    for action_id in &binding.action_ids {
        let item_id = binding
            .item_by_action
            .get(action_id)
            .ok_or(AuditError::AuthorizationBindingMismatch)?;
        let risk = binding
            .risk_by_action
            .get(action_id)
            .copied()
            .ok_or(AuditError::AuthorizationBindingMismatch)?;
        transaction.execute(
            "INSERT INTO authorization_actions VALUES(?1,?2,?3,?4)",
            params![
                binding.authorization_id.as_str(),
                action_id.as_str(),
                item_id.as_str(),
                risk_db(risk)
            ],
        )?;
    }
    Ok(())
}

fn load_authorization(
    transaction: &Transaction<'_>,
    authorization_id: &AuthorizationId,
) -> Result<(AuthorizationBinding, String, Option<i64>, Option<String>), AuditError> {
    transaction.query_row(
        "SELECT binding_json,state,current_fence_epoch,current_execution_id FROM authorizations WHERE authorization_id=?1",
        [authorization_id.as_str()],
        |row| Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional()?.map(|(json, state, fence, execution)| -> Result<_, AuditError> {
        let binding: AuthorizationBinding = serde_json::from_str(&json).map_err(AuditError::JournalDecode)?;
        validate_binding(&binding)?;
        Ok((binding, state, fence, execution))
    }).transpose()?.ok_or_else(|| AuditError::AuthorizationUnknown(authorization_id.as_str().to_string()))
}

fn load_intent(
    transaction: &Transaction<'_>,
    attempt_id: &AttemptId,
) -> Result<(IntentAuthority, String), AuditError> {
    transaction
        .query_row(
            "SELECT authority_json,terminal_state FROM intents WHERE attempt_id=?1",
            [attempt_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get(1)?)),
        )
        .optional()?
        .map(|(json, state)| -> Result<_, AuditError> {
            let authority = serde_json::from_str(&json).map_err(AuditError::JournalDecode)?;
            Ok((authority, state))
        })
        .transpose()?
        .ok_or_else(|| AuditError::IntentNotFound(attempt_id.as_str().to_string()))
}

fn load_recovery_candidates(
    connection: &Connection,
    authorization_id: &AuthorizationId,
) -> Result<(Vec<IntentAuthority>, Vec<RecoveryRecord>), AuditError> {
    let mut statement = connection.prepare("SELECT authority_json,terminal_state FROM intents WHERE authorization_id=?1 ORDER BY ordinal")?;
    let rows = statement.query_map([authorization_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut reserved = Vec::new();
    let mut existing = Vec::new();
    for row in rows {
        let (json, state) = row?;
        let authority: IntentAuthority =
            serde_json::from_str(&json).map_err(AuditError::JournalDecode)?;
        if state == "reserved" {
            reserved.push(authority);
        } else if state.starts_with("classified_") {
            let record_json: String = connection.query_row(
                "SELECT record_json FROM recoveries WHERE attempt_id=?1",
                [authority.attempt_id.as_str()],
                |row| row.get(0),
            )?;
            existing.push(serde_json::from_str(&record_json).map_err(AuditError::JournalDecode)?);
        }
    }
    Ok((reserved, existing))
}

fn validate_live_claim(
    transaction: &Transaction<'_>,
    claimed: &ClaimedExecution,
) -> Result<(), AuditError> {
    let valid: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM authorizations a JOIN executions e ON e.execution_id=a.current_execution_id WHERE a.authorization_id=?1 AND a.state='claimed' AND a.current_execution_id=?2 AND a.current_fence_epoch=?3 AND e.state='active' AND e.fence_epoch=?3)",
        params![claimed.authorization_id().as_str(), claimed.execution_id, claimed.fence_epoch as i64], |row| row.get(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(AuditError::FenceEpochMismatch)
    }
}

fn validate_live_claim_connection(
    connection: &Connection,
    claimed: &ClaimedExecution,
) -> Result<(), AuditError> {
    let valid: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM authorizations a JOIN executions e ON e.execution_id=a.current_execution_id WHERE a.authorization_id=?1 AND a.state='claimed' AND a.current_execution_id=?2 AND a.current_fence_epoch=?3 AND e.state='active' AND e.fence_epoch=?3)",
        params![claimed.authorization_id().as_str(), claimed.execution_id, claimed.fence_epoch as i64], |row| row.get(0),
    )?;
    if valid {
        Ok(())
    } else {
        Err(AuditError::FenceEpochMismatch)
    }
}

fn append_event(transaction: &Transaction<'_>, payload: &EventPayload) -> Result<u64, AuditError> {
    let event_count: i64 =
        transaction.query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))?;
    if event_count >= MAX_EVENTS {
        return Err(AuditError::JournalTooLarge);
    }
    let (sequence, previous_digest): (i64, Option<String>) = transaction.query_row(
        "SELECT sequence,digest FROM audit_head WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let next = sequence
        .checked_add(1)
        .ok_or(AuditError::FenceEpochOverflow)?;
    let recorded_at_ms = unix_ms_i64(SystemTime::now())?;
    let monotonic_elapsed_ns = monotonic_elapsed_ns().to_string();
    let payload_json = canonical_json(payload)?;
    if payload_json.len() > MAX_RECORD_BYTES {
        return Err(AuditError::RecordTooLarge);
    }
    let (authorization_id, action_id, attempt_id) = payload.indexed_ids();
    let digest = digest_event(
        next as u64,
        recorded_at_ms,
        &monotonic_elapsed_ns,
        payload.kind(),
        authorization_id,
        action_id,
        attempt_id,
        previous_digest.as_deref(),
        payload_json.as_bytes(),
    );
    transaction.execute(
        "INSERT INTO audit_events(sequence,recorded_at_ms,monotonic_elapsed_ns,kind,authorization_id,action_id,attempt_id,previous_digest,payload_json,digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![next, recorded_at_ms, monotonic_elapsed_ns, payload.kind(), authorization_id, action_id, attempt_id, previous_digest, payload_json, digest],
    )?;
    let changed = transaction.execute(
        "UPDATE audit_head SET sequence=?1,digest=?2 WHERE singleton=1 AND sequence=?3",
        params![next, digest, sequence],
    )?;
    if changed != 1 {
        return Err(AuditError::HeadMismatch);
    }
    Ok(next as u64)
}

#[derive(Default)]
struct ReplayedProjection {
    authorizations: BTreeMap<String, ReplayedAuthorization>,
    executions: BTreeMap<String, ReplayedExecution>,
    intents: BTreeMap<String, ReplayedIntent>,
    outcomes: BTreeMap<String, String>,
    recoveries: BTreeMap<String, (String, String)>,
    next_fence_epoch: i64,
    next_attempt_ordinal: i64,
}

struct ReplayedAuthorization {
    plan_digest: String,
    binding_json: String,
    state: String,
    current_fence_epoch: Option<i64>,
    current_execution_id: Option<String>,
}

struct ReplayedExecution {
    authorization_id: String,
    fence_epoch: i64,
    kind: String,
    state: String,
    started_at_ms: i64,
    ended_at_ms: Option<i64>,
}

struct ReplayedIntent {
    ordinal: i64,
    nonce: String,
    authorization_id: String,
    execution_id: String,
    fence_epoch: i64,
    item_id: String,
    action_id: String,
    source_path_hash: String,
    before_revalidation_digest: String,
    authority_json: String,
    terminal_state: String,
}

fn replay_event(
    projection: &mut ReplayedProjection,
    payload: &EventPayload,
) -> Result<(), AuditError> {
    match payload {
        EventPayload::AuthorizationRegistered { binding } => {
            let authorization_id = binding.authorization_id.as_str().to_string();
            if projection
                .authorizations
                .insert(
                    authorization_id,
                    ReplayedAuthorization {
                        plan_digest: binding.plan_digest.as_str().to_string(),
                        binding_json: canonical_json(binding)?,
                        state: "unused".to_string(),
                        current_fence_epoch: None,
                        current_execution_id: None,
                    },
                )
                .is_some()
            {
                return Err(AuditError::HeadMismatch);
            }
        }
        EventPayload::ExecutionClaimed {
            authorization_id,
            execution_id,
            fence_epoch,
            started_at_unix_ms,
        } => {
            replay_claim(
                projection,
                authorization_id,
                execution_id,
                *fence_epoch,
                "execution",
                started_at_unix_ms,
                None,
            )?;
        }
        EventPayload::RecoveryClaimed {
            authorization_id,
            previous_execution_id,
            execution_id,
            fence_epoch,
            started_at_unix_ms,
        } => {
            replay_claim(
                projection,
                authorization_id,
                execution_id,
                *fence_epoch,
                "recovery",
                started_at_unix_ms,
                Some(previous_execution_id),
            )?;
        }
        EventPayload::ActionIntent { authority } => {
            projection.next_attempt_ordinal = projection
                .next_attempt_ordinal
                .checked_add(1)
                .ok_or(AuditError::HeadMismatch)?;
            let attempt_id = authority.attempt_id.as_str().to_string();
            if projection.intents.values().any(|intent| {
                intent.authorization_id == authority.authorization_id.as_str()
                    && intent.action_id == authority.action_id.as_str()
            }) {
                return Err(AuditError::HeadMismatch);
            }
            if projection
                .intents
                .insert(
                    attempt_id,
                    ReplayedIntent {
                        ordinal: projection.next_attempt_ordinal,
                        nonce: authority.nonce.as_str().to_string(),
                        authorization_id: authority.authorization_id.as_str().to_string(),
                        execution_id: authority.execution_id.clone(),
                        fence_epoch: authority.fence_epoch as i64,
                        item_id: authority.item_id.as_str().to_string(),
                        action_id: authority.action_id.as_str().to_string(),
                        source_path_hash: authority.source_path_hash.as_str().to_string(),
                        before_revalidation_digest: authority
                            .before_revalidation_digest
                            .as_str()
                            .to_string(),
                        authority_json: canonical_json(authority)?,
                        terminal_state: "reserved".to_string(),
                    },
                )
                .is_some()
            {
                return Err(AuditError::HeadMismatch);
            }
        }
        EventPayload::ActionOutcome { outcome } | EventPayload::RecoveryOutcome { outcome, .. } => {
            let attempt = outcome.authority.attempt_id.as_str().to_string();
            let intent = projection
                .intents
                .get_mut(&attempt)
                .ok_or(AuditError::HeadMismatch)?;
            intent.terminal_state = "outcome_recorded".to_string();
            projection.recoveries.remove(&attempt);
            projection
                .outcomes
                .insert(attempt, canonical_json(outcome)?);
        }
        EventPayload::RecoveryClassification { authority, record } => {
            let attempt = authority.attempt_id.as_str().to_string();
            let intent = projection
                .intents
                .get_mut(&attempt)
                .ok_or(AuditError::HeadMismatch)?;
            intent.terminal_state = terminal_for_disposition(record.disposition).to_string();
            projection.recoveries.insert(
                attempt,
                (
                    disposition_db(record.disposition).to_string(),
                    canonical_json(record)?,
                ),
            );
        }
        EventPayload::ExecutionConsumed {
            authorization_id,
            execution_id,
            fence_epoch,
            ended_at_unix_ms,
        } => {
            let authorization = projection
                .authorizations
                .get_mut(authorization_id.as_str())
                .ok_or(AuditError::HeadMismatch)?;
            if authorization.current_execution_id.as_deref() != Some(execution_id)
                || authorization.current_fence_epoch != Some(*fence_epoch as i64)
            {
                return Err(AuditError::HeadMismatch);
            }
            authorization.state = "consumed".to_string();
            authorization.current_execution_id = None;
            let execution = projection
                .executions
                .get_mut(execution_id)
                .ok_or(AuditError::HeadMismatch)?;
            execution.state = "consumed".to_string();
            execution.ended_at_ms = Some(parse_event_i64(ended_at_unix_ms)?);
        }
    }
    Ok(())
}

fn replay_claim(
    projection: &mut ReplayedProjection,
    authorization_id: &AuthorizationId,
    execution_id: &str,
    fence_epoch: u64,
    kind: &str,
    started_at: &str,
    previous_execution: Option<&String>,
) -> Result<(), AuditError> {
    let fence = i64::try_from(fence_epoch).map_err(|_| AuditError::HeadMismatch)?;
    if fence
        != projection
            .next_fence_epoch
            .checked_add(1)
            .ok_or(AuditError::HeadMismatch)?
    {
        return Err(AuditError::HeadMismatch);
    }
    if let Some(previous) = previous_execution {
        let previous = projection
            .executions
            .get_mut(previous)
            .ok_or(AuditError::HeadMismatch)?;
        previous.state = "superseded".to_string();
        previous.ended_at_ms = Some(parse_event_i64(started_at)?);
    } else if projection
        .authorizations
        .get(authorization_id.as_str())
        .is_none_or(|authorization| authorization.state != "unused")
    {
        return Err(AuditError::HeadMismatch);
    }
    projection.next_fence_epoch = fence;
    projection.executions.insert(
        execution_id.to_string(),
        ReplayedExecution {
            authorization_id: authorization_id.as_str().to_string(),
            fence_epoch: fence,
            kind: kind.to_string(),
            state: "active".to_string(),
            started_at_ms: parse_event_i64(started_at)?,
            ended_at_ms: None,
        },
    );
    let authorization = projection
        .authorizations
        .get_mut(authorization_id.as_str())
        .ok_or(AuditError::HeadMismatch)?;
    authorization.state = "claimed".to_string();
    authorization.current_fence_epoch = Some(fence);
    authorization.current_execution_id = Some(execution_id.to_string());
    Ok(())
}

fn parse_event_i64(value: &str) -> Result<i64, AuditError> {
    value.parse().map_err(|_| AuditError::HeadMismatch)
}

fn replay_projection(connection: &Connection) -> Result<ReplayedProjection, AuditError> {
    verify_connection_pragmas(connection)?;
    verify_initialized_database(connection)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(AuditError::IntegrityCheckFailed(integrity));
    }
    let foreign_violation: Option<(String, i64)> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()?;
    if let Some((table, row)) = foreign_violation {
        return Err(AuditError::IntegrityCheckFailed(format!(
            "foreign key violation in {table} row {row}"
        )));
    }
    let mut statement = connection.prepare("SELECT sequence,recorded_at_ms,monotonic_elapsed_ns,kind,authorization_id,action_id,attempt_id,previous_digest,payload_json,digest FROM audit_events ORDER BY sequence")?;
    let mut rows = statement.query([])?;
    let mut expected_sequence = 1_u64;
    let mut previous: Option<String> = None;
    let mut replayed = ReplayedProjection::default();
    while let Some(row) = rows.next()? {
        let sequence: i64 = row.get(0)?;
        if sequence < 1 || sequence as u64 != expected_sequence {
            return Err(AuditError::JournalTampered {
                sequence: sequence.max(0) as u64,
                reason: "non-contiguous sequence".to_string(),
            });
        }
        let recorded_at_ms: i64 = row.get(1)?;
        let monotonic: String = row.get(2)?;
        let kind: String = row.get(3)?;
        let authorization_id: Option<String> = row.get(4)?;
        let action_id: Option<String> = row.get(5)?;
        let attempt_id: Option<String> = row.get(6)?;
        let stored_previous: Option<String> = row.get(7)?;
        let payload_json: String = row.get(8)?;
        let stored_digest: String = row.get(9)?;
        if stored_previous != previous {
            return Err(AuditError::JournalTampered {
                sequence: expected_sequence,
                reason: "previous digest mismatch".to_string(),
            });
        }
        let payload: EventPayload =
            serde_json::from_str(&payload_json).map_err(AuditError::JournalDecode)?;
        let canonical = canonical_json(&payload)?;
        if canonical != payload_json || payload.kind() != kind {
            return Err(AuditError::JournalTampered {
                sequence: expected_sequence,
                reason: "payload or event kind mismatch".to_string(),
            });
        }
        let indexed = payload.indexed_ids();
        if indexed.0 != authorization_id.as_deref()
            || indexed.1 != action_id.as_deref()
            || indexed.2 != attempt_id.as_deref()
        {
            return Err(AuditError::JournalTampered {
                sequence: expected_sequence,
                reason: "indexed event fields mismatch".to_string(),
            });
        }
        let expected_digest = digest_event(
            expected_sequence,
            recorded_at_ms,
            &monotonic,
            &kind,
            indexed.0,
            indexed.1,
            indexed.2,
            stored_previous.as_deref(),
            payload_json.as_bytes(),
        );
        if stored_digest != expected_digest {
            return Err(AuditError::JournalTampered {
                sequence: expected_sequence,
                reason: "event digest mismatch".to_string(),
            });
        }
        replay_event(&mut replayed, &payload)?;
        previous = Some(stored_digest);
        expected_sequence += 1;
    }
    let (head_sequence, head_digest): (i64, Option<String>) = connection.query_row(
        "SELECT sequence,digest FROM audit_head WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if head_sequence != (expected_sequence - 1) as i64 || head_digest != previous {
        return Err(AuditError::HeadMismatch);
    }
    Ok(replayed)
}

fn verify_database(connection: &Connection) -> Result<IntegritySummary, AuditError> {
    let replayed = replay_projection(connection)?;
    let (head_sequence, head_digest): (i64, Option<String>) = connection.query_row(
        "SELECT sequence,digest FROM audit_head WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    verify_replayed_projection(connection, &replayed)?;
    let action_sequence: i64 = connection.query_row(
        "SELECT count(*) FROM audit_events WHERE kind IN ('action_intent','action_outcome','recovery_outcome','recovery_classification')",
        [],
        |row| row.get(0),
    )?;
    Ok(IntegritySummary {
        latest_sequence: head_sequence as u64,
        action_sequence: action_sequence as u64,
        latest_digest: head_digest,
    })
}

fn verify_replayed_projection(
    connection: &Connection,
    replayed: &ReplayedProjection,
) -> Result<(), AuditError> {
    let meta: (i64, i64) = connection.query_row(
        "SELECT next_fence_epoch,next_attempt_ordinal FROM store_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if meta != (replayed.next_fence_epoch, replayed.next_attempt_ordinal) {
        return Err(AuditError::HeadMismatch);
    }

    let mut actual_authorizations = BTreeMap::new();
    let mut statement = connection.prepare("SELECT authorization_id,plan_digest,binding_json,state,current_fence_epoch,current_execution_id FROM authorizations ORDER BY authorization_id")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })? {
        let (id, plan, binding, state, fence, execution) = row?;
        actual_authorizations.insert(id, (plan, binding, state, fence, execution));
    }
    let expected_authorizations = replayed
        .authorizations
        .iter()
        .map(|(id, value)| {
            (
                id.clone(),
                (
                    value.plan_digest.clone(),
                    value.binding_json.clone(),
                    value.state.clone(),
                    value.current_fence_epoch,
                    value.current_execution_id.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual_authorizations != expected_authorizations {
        return Err(AuditError::HeadMismatch);
    }

    let mut actual_executions = BTreeMap::new();
    let mut statement = connection.prepare("SELECT execution_id,authorization_id,fence_epoch,kind,state,started_at_ms,ended_at_ms FROM executions ORDER BY execution_id")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, Option<i64>>(6)?,
        ))
    })? {
        let (id, auth, fence, kind, state, started, ended) = row?;
        actual_executions.insert(id, (auth, fence, kind, state, started, ended));
    }
    let expected_executions = replayed
        .executions
        .iter()
        .map(|(id, value)| {
            (
                id.clone(),
                (
                    value.authorization_id.clone(),
                    value.fence_epoch,
                    value.kind.clone(),
                    value.state.clone(),
                    value.started_at_ms,
                    value.ended_at_ms,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual_executions != expected_executions {
        return Err(AuditError::HeadMismatch);
    }

    let mut actual_intents = BTreeMap::new();
    let mut statement = connection.prepare("SELECT attempt_id,ordinal,nonce,authorization_id,execution_id,fence_epoch,item_id,action_id,source_path_hash,before_revalidation_digest,authority_json,terminal_state FROM intents ORDER BY attempt_id")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, String>(9)?,
            row.get::<_, String>(10)?,
            row.get::<_, String>(11)?,
        ))
    })? {
        let (
            id,
            ordinal,
            nonce,
            auth,
            execution,
            fence,
            item,
            action,
            path_hash,
            revalidation,
            authority,
            terminal,
        ) = row?;
        actual_intents.insert(
            id,
            (
                ordinal,
                nonce,
                auth,
                execution,
                fence,
                item,
                action,
                path_hash,
                revalidation,
                authority,
                terminal,
            ),
        );
    }
    let expected_intents = replayed
        .intents
        .iter()
        .map(|(id, value)| {
            (
                id.clone(),
                (
                    value.ordinal,
                    value.nonce.clone(),
                    value.authorization_id.clone(),
                    value.execution_id.clone(),
                    value.fence_epoch,
                    value.item_id.clone(),
                    value.action_id.clone(),
                    value.source_path_hash.clone(),
                    value.before_revalidation_digest.clone(),
                    value.authority_json.clone(),
                    value.terminal_state.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual_intents != expected_intents {
        return Err(AuditError::HeadMismatch);
    }

    let actual_outcomes = read_string_map(
        connection,
        "SELECT attempt_id,outcome_json FROM outcomes ORDER BY attempt_id",
    )?;
    if actual_outcomes != replayed.outcomes {
        return Err(AuditError::HeadMismatch);
    }
    let mut actual_recoveries = BTreeMap::new();
    let mut statement = connection
        .prepare("SELECT attempt_id,disposition,record_json FROM recoveries ORDER BY attempt_id")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })? {
        let (id, disposition, record) = row?;
        actual_recoveries.insert(id, (disposition, record));
    }
    if actual_recoveries != replayed.recoveries {
        return Err(AuditError::HeadMismatch);
    }

    for authorization in replayed.authorizations.values() {
        let binding: AuthorizationBinding =
            serde_json::from_str(&authorization.binding_json).map_err(AuditError::JournalDecode)?;
        let actual_items = read_string_set(
            connection,
            "SELECT item_id FROM authorization_items WHERE authorization_id=?1 ORDER BY item_id",
            binding.authorization_id.as_str(),
        )?;
        let expected_items = binding
            .item_ids
            .iter()
            .map(|item| item.as_str().to_string())
            .collect::<BTreeSet<_>>();
        if actual_items != expected_items {
            return Err(AuditError::HeadMismatch);
        }
        let mut actual_actions = BTreeMap::new();
        let mut statement = connection.prepare("SELECT action_id,item_id,risk FROM authorization_actions WHERE authorization_id=?1 ORDER BY action_id")?;
        for row in statement.query_map([binding.authorization_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (action, item, risk) = row?;
            actual_actions.insert(action, (item, risk));
        }
        let expected_actions = binding
            .action_ids
            .iter()
            .map(|action| {
                (
                    action.as_str().to_string(),
                    (
                        binding.item_by_action[action].as_str().to_string(),
                        risk_db(binding.risk_by_action[action]).to_string(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if actual_actions != expected_actions {
            return Err(AuditError::HeadMismatch);
        }
    }
    Ok(())
}

fn projection_state_from_flags(
    has_authorized: bool,
    has_pending: bool,
    has_indeterminate: bool,
) -> AuditProjectionState {
    if has_indeterminate {
        AuditProjectionState::Indeterminate
    } else if has_pending {
        AuditProjectionState::Pending
    } else if has_authorized {
        AuditProjectionState::Authorized
    } else {
        AuditProjectionState::Terminal
    }
}

fn recovery_disposition_from_db(value: &str) -> Result<AuditRecoveryDisposition, AuditError> {
    match value {
        "pending" => Ok(AuditRecoveryDisposition::Pending),
        "reserved" => Ok(AuditRecoveryDisposition::Reserved),
        "indeterminate" => Ok(AuditRecoveryDisposition::Indeterminate),
        _ => Err(AuditError::HeadMismatch),
    }
}

fn action_projection_from_replay(
    replayed: &ReplayedProjection,
    attempt_id: &str,
    intent: &ReplayedIntent,
) -> Result<AuditActionProjection, AuditError> {
    let mut state = AuditProjectionState::Terminal;
    let mut needs_reconciliation = false;
    let mut recovery_disposition = None;

    let terminal_outcome = replayed
        .outcomes
        .get(attempt_id)
        .map(
            |json| -> Result<AuditTerminalOutcomeProjection, AuditError> {
                let outcome: OutcomeEvent =
                    serde_json::from_str(json).map_err(AuditError::JournalDecode)?;
                Ok(AuditTerminalOutcomeProjection {
                    stable_status: match outcome.stable_status {
                        StableStatus::TrashSucceededPlatformReported => {
                            AuditStableStatus::TrashSucceededPlatformReported
                        }
                        StableStatus::TrashSucceededLocationReported => {
                            AuditStableStatus::TrashSucceededLocationReported
                        }
                        StableStatus::PermanentDeleteSucceeded => {
                            AuditStableStatus::PermanentDeleteSucceeded
                        }
                        StableStatus::FailedPlatformError => AuditStableStatus::FailedPlatformError,
                        StableStatus::FailedCancelledByPlatform => {
                            AuditStableStatus::FailedCancelledByPlatform
                        }
                        StableStatus::FailedSourceUnchanged => {
                            AuditStableStatus::FailedSourceUnchanged
                        }
                        StableStatus::VanishedBeforeAction => {
                            AuditStableStatus::VanishedBeforeAction
                        }
                        StableStatus::CancelledBeforeAction => {
                            AuditStableStatus::CancelledBeforeAction
                        }
                        StableStatus::IndeterminateAfterCrash => {
                            AuditStableStatus::IndeterminateAfterCrash
                        }
                        StableStatus::IndeterminatePlatformResult => {
                            AuditStableStatus::IndeterminatePlatformResult
                        }
                    },
                    recovery_state: match outcome.recovery_state {
                        RecoveryState::PlatformTrashReported => {
                            AuditOutcomeRecoveryState::PlatformTrashReported
                        }
                        RecoveryState::TrashLocationReported => {
                            AuditOutcomeRecoveryState::TrashLocationReported
                        }
                        RecoveryState::InapplicablePermanent => {
                            AuditOutcomeRecoveryState::InapplicablePermanent
                        }
                        RecoveryState::FailedSourceUnchanged => {
                            AuditOutcomeRecoveryState::FailedSourceUnchanged
                        }
                        RecoveryState::CancelledBeforeAction => {
                            AuditOutcomeRecoveryState::CancelledBeforeAction
                        }
                        RecoveryState::VanishedBeforeAction => {
                            AuditOutcomeRecoveryState::VanishedBeforeAction
                        }
                        RecoveryState::Indeterminate => AuditOutcomeRecoveryState::Indeterminate,
                    },
                })
            },
        )
        .transpose()?;

    match intent.terminal_state.as_str() {
        "outcome_recorded" => {
            if terminal_outcome.as_ref().is_some_and(|outcome| {
                outcome.recovery_state == AuditOutcomeRecoveryState::Indeterminate
            }) {
                state = AuditProjectionState::Indeterminate;
                needs_reconciliation = true;
            }
        }
        "reserved" | "classified_reserved" => {
            state = AuditProjectionState::Pending;
            needs_reconciliation = true;
            recovery_disposition = if intent.terminal_state == "classified_reserved" {
                Some(AuditRecoveryDisposition::Reserved)
            } else {
                None
            };
        }
        "classified_pending" => {
            state = AuditProjectionState::Pending;
            needs_reconciliation = true;
            recovery_disposition = Some(AuditRecoveryDisposition::Pending);
        }
        "classified_indeterminate" => {
            state = AuditProjectionState::Indeterminate;
            needs_reconciliation = true;
            recovery_disposition = Some(AuditRecoveryDisposition::Indeterminate);
        }
        _ => return Err(AuditError::HeadMismatch),
    }

    if let Some((disposition, _)) = replayed.recoveries.get(attempt_id) {
        recovery_disposition = Some(recovery_disposition_from_db(disposition)?);
    }

    Ok(AuditActionProjection {
        authorization_id: intent.authorization_id.clone(),
        item_id: intent.item_id.clone(),
        action_id: intent.action_id.clone(),
        attempt_id: Some(attempt_id.to_string()),
        state,
        needs_reconciliation,
        recovery_disposition,
        terminal_outcome,
    })
}

fn projection_snapshot_from_replay(
    replayed: &ReplayedProjection,
) -> Result<AuditProjectionSnapshot, AuditError> {
    let mut batches =
        BTreeMap::<String, BTreeMap<String, BTreeMap<String, Vec<AuditActionProjection>>>>::new();

    for authorization in replayed.authorizations.values() {
        let binding: AuthorizationBinding =
            serde_json::from_str(&authorization.binding_json).map_err(AuditError::JournalDecode)?;
        validate_binding(&binding)?;
        let batch = batches
            .entry(binding.batch_id.as_str().to_string())
            .or_default();
        for item in &binding.item_ids {
            batch
                .entry(item.as_str().to_string())
                .or_default()
                .entry(binding.authorization_id.as_str().to_string())
                .or_default();
        }
        for action in &binding.action_ids {
            let item = binding
                .item_by_action
                .get(action)
                .ok_or(AuditError::HeadMismatch)?
                .as_str()
                .to_string();
            batch
                .entry(item)
                .or_default()
                .entry(binding.authorization_id.as_str().to_string())
                .or_default()
                .push(AuditActionProjection {
                    authorization_id: binding.authorization_id.as_str().to_string(),
                    item_id: binding.item_by_action[action].as_str().to_string(),
                    action_id: action.as_str().to_string(),
                    attempt_id: None,
                    state: AuditProjectionState::Authorized,
                    needs_reconciliation: false,
                    recovery_disposition: None,
                    terminal_outcome: None,
                });
        }
    }

    for (attempt_id, intent) in &replayed.intents {
        let action = action_projection_from_replay(replayed, attempt_id, intent)?;
        let authorization = replayed
            .authorizations
            .get(&intent.authorization_id)
            .ok_or(AuditError::HeadMismatch)?;
        let binding: AuthorizationBinding =
            serde_json::from_str(&authorization.binding_json).map_err(AuditError::JournalDecode)?;
        let batch = batches
            .get_mut(binding.batch_id.as_str())
            .ok_or(AuditError::HeadMismatch)?;
        let authorizations = batch
            .get_mut(&intent.item_id)
            .ok_or(AuditError::HeadMismatch)?;
        let actions = authorizations
            .get_mut(&intent.authorization_id)
            .ok_or(AuditError::HeadMismatch)?;
        let slot = actions
            .iter_mut()
            .find(|candidate| candidate.action_id == action.action_id)
            .ok_or(AuditError::HeadMismatch)?;
        *slot = action;
    }

    let mut batch_list = Vec::new();
    for (batch_id, items) in batches {
        let mut item_list = Vec::new();
        let mut batch_has_authorized = false;
        let mut batch_has_pending = false;
        let mut batch_has_indeterminate = false;
        for (item_id, authorizations) in items {
            let mut authorization_list = Vec::new();
            let mut item_has_authorized = false;
            let mut item_has_pending = false;
            let mut item_has_indeterminate = false;
            for (authorization_id, mut actions) in authorizations {
                actions.sort_by(|left, right| left.action_id.cmp(&right.action_id));
                let auth_has_authorized = actions
                    .iter()
                    .any(|action| action.state == AuditProjectionState::Authorized);
                let auth_has_pending = actions
                    .iter()
                    .any(|action| action.state == AuditProjectionState::Pending);
                let auth_has_indeterminate = actions
                    .iter()
                    .any(|action| action.state == AuditProjectionState::Indeterminate);
                item_has_authorized |= auth_has_authorized;
                item_has_pending |= auth_has_pending;
                item_has_indeterminate |= auth_has_indeterminate;
                authorization_list.push(AuditAuthorizationProjection {
                    authorization_id,
                    state: projection_state_from_flags(
                        auth_has_authorized,
                        auth_has_pending,
                        auth_has_indeterminate,
                    ),
                    needs_reconciliation: auth_has_pending || auth_has_indeterminate,
                    actions,
                });
            }
            authorization_list
                .sort_by(|left, right| left.authorization_id.cmp(&right.authorization_id));
            batch_has_authorized |= item_has_authorized;
            batch_has_pending |= item_has_pending;
            batch_has_indeterminate |= item_has_indeterminate;
            item_list.push(AuditItemProjection {
                item_id,
                state: projection_state_from_flags(
                    item_has_authorized,
                    item_has_pending,
                    item_has_indeterminate,
                ),
                needs_reconciliation: item_has_pending || item_has_indeterminate,
                authorizations: authorization_list,
            });
        }
        item_list.sort_by(|left, right| left.item_id.cmp(&right.item_id));
        batch_list.push(AuditBatchProjection {
            batch_id,
            state: projection_state_from_flags(
                batch_has_authorized,
                batch_has_pending,
                batch_has_indeterminate,
            ),
            needs_reconciliation: batch_has_pending || batch_has_indeterminate,
            items: item_list,
        });
    }
    batch_list.sort_by(|left, right| left.batch_id.cmp(&right.batch_id));
    Ok(AuditProjectionSnapshot::new(batch_list))
}

fn read_string_map(
    connection: &Connection,
    sql: &str,
) -> Result<BTreeMap<String, String>, AuditError> {
    let mut statement = connection.prepare(sql)?;
    let mut values = BTreeMap::new();
    for row in statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (key, value) = row?;
        values.insert(key, value);
    }
    Ok(values)
}

fn read_string_set(
    connection: &Connection,
    sql: &str,
    parameter: &str,
) -> Result<BTreeSet<String>, AuditError> {
    let mut statement = connection.prepare(sql)?;
    let mut values = BTreeSet::new();
    for row in statement.query_map([parameter], |row| row.get::<_, String>(0))? {
        values.insert(row?);
    }
    Ok(values)
}

#[allow(clippy::too_many_arguments)] // Every indexed field is explicitly committed into the hash envelope.
fn digest_event(
    sequence: u64,
    recorded_at_ms: i64,
    monotonic: &str,
    kind: &str,
    authorization_id: Option<&str>,
    action_id: Option<&str>,
    attempt_id: Option<&str>,
    previous: Option<&str>,
    payload: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hash_part(&mut hasher, &sequence.to_be_bytes());
    hash_part(&mut hasher, &recorded_at_ms.to_be_bytes());
    hash_part(&mut hasher, monotonic.as_bytes());
    hash_part(&mut hasher, kind.as_bytes());
    for part in [authorization_id, action_id, attempt_id, previous] {
        hash_part(&mut hasher, part.unwrap_or("").as_bytes());
    }
    hash_part(&mut hasher, payload);
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

fn hash_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

struct ValidatedOutcome {
    actual_platform_operation: String,
    adapter_version: String,
    started_at_ms: i64,
    finished_at_ms: i64,
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

fn validate_binding(binding: &AuthorizationBinding) -> Result<(), AuditError> {
    let action_len = binding.action_ids.len();
    if action_len == 0
        || action_len > MAX_ACTIONS_PER_AUTHORIZATION
        || binding.item_ids.is_empty()
        || binding.item_ids.len() > MAX_ACTIONS_PER_AUTHORIZATION
        || binding.action_count != action_len as u64
        || binding.item_by_action.len() != action_len
        || binding.risk_by_action.len() != action_len
        || binding.item_by_action.keys().ne(binding.action_ids.iter())
        || binding.risk_by_action.keys().ne(binding.action_ids.iter())
        || binding
            .item_by_action
            .values()
            .any(|item| !binding.item_ids.contains(item))
        || binding
            .item_by_action
            .values()
            .cloned()
            .collect::<BTreeSet<_>>()
            != binding.item_ids
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    validate_bounded_field(
        &binding.policy_version,
        "policy_version",
        MAX_SHORT_FIELD_BYTES,
    )?;
    if binding.policy_version.is_empty() {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    match (binding.authorization_source, binding.requested_mode) {
        (AuthorizationSource::ExplicitDangerousDelete, RequestedMode::Permanent)
            if binding
                .risk_by_action
                .values()
                .all(|risk| *risk == RiskTier::R4) => {}
        (AuthorizationSource::ExplicitDangerousDelete, _) => {
            return Err(AuditError::AuthorizationBindingMismatch);
        }
        _ => {}
    }
    if binding.authorization_source != AuthorizationSource::DeterministicSimulation {
        return Err(AuditError::NonSimulationAuthorizationRejected);
    }
    Ok(())
}

fn validate_intent_binding(
    binding: &AuthorizationBinding,
    request: &IntentRequest,
) -> Result<(), AuditError> {
    if binding.item_by_action.get(&request.action_id) != Some(&request.item_id)
        || !binding.risk_by_action.contains_key(&request.action_id)
    {
        return Err(AuditError::ActionNotAuthorized);
    }
    Ok(())
}

fn validate_authority_binding(
    authority: &IntentAuthority,
    binding: &AuthorizationBinding,
) -> Result<(), AuditError> {
    if authority.authorization_id != binding.authorization_id
        || authority.authorization_source != binding.authorization_source
        || authority.batch_id != binding.batch_id
        || authority.plan_id != binding.plan_id
        || authority.plan_digest != binding.plan_digest
        || authority.requested_mode != binding.requested_mode
        || binding.item_by_action.get(&authority.action_id) != Some(&authority.item_id)
        || binding.risk_by_action.get(&authority.action_id) != Some(&authority.risk_tier)
        || authority.policy_version != binding.policy_version
        || authority.policy_digest != binding.policy_digest
        || authority.protected_anchor_snapshot_digest != binding.protected_anchor_snapshot_digest
        || authority.adapter_capabilities_digest != binding.adapter_capabilities_digest
        || authority.cleaner_set_digest != binding.cleaner_set_digest
        || authority.host_instance_id != binding.host_instance_id
        || authority.user_identity != binding.user_identity
        || authority.workflow_session != binding.workflow_session
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn ensure_claim_matches_token(
    claimed: &ClaimedExecution,
    token: &DurableIntentToken,
) -> Result<(), AuditError> {
    if token.database_id != claimed.database_id
        || token.execution_id != claimed.execution_id
        || token.authorization_id != claimed.binding.authorization_id
        || token.authorization_source != claimed.binding.authorization_source
        || token.batch_id != claimed.binding.batch_id
        || token.plan_id != claimed.binding.plan_id
        || token.plan_digest != claimed.binding.plan_digest
        || token.requested_mode != claimed.binding.requested_mode
        || token.fence_epoch != claimed.fence_epoch
        || token.policy_version != claimed.binding.policy_version
        || token.policy_digest != claimed.binding.policy_digest
        || token.protected_anchor_snapshot_digest
            != claimed.binding.protected_anchor_snapshot_digest
        || token.adapter_capabilities_digest != claimed.binding.adapter_capabilities_digest
        || token.cleaner_set_digest != claimed.binding.cleaner_set_digest
        || token.host_instance_id != claimed.binding.host_instance_id
        || token.user_identity != claimed.binding.user_identity
        || token.workflow_session != claimed.binding.workflow_session
        || claimed.binding.item_by_action.get(&token.action_id) != Some(&token.item_id)
        || claimed.binding.risk_by_action.get(&token.action_id) != Some(&token.risk_tier)
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
        || token.database_id != authority.database_id
        || token.execution_id != authority.execution_id
        || token.authorization_id != authority.authorization_id
        || token.authorization_source != authority.authorization_source
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
        || token.policy_version != authority.policy_version
        || token.policy_digest != authority.policy_digest
        || token.protected_anchor_snapshot_digest != authority.protected_anchor_snapshot_digest
        || token.adapter_capabilities_digest != authority.adapter_capabilities_digest
        || token.cleaner_set_digest != authority.cleaner_set_digest
        || token.host_instance_id != authority.host_instance_id
        || token.user_identity != authority.user_identity
        || token.workflow_session != authority.workflow_session
    {
        return Err(AuditError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_outcome(
    token: &DurableIntentToken,
    outcome: SimulatedOutcome,
) -> Result<ValidatedOutcome, AuditError> {
    validate_outcome_shape(token.requested_mode, &outcome)?;
    let started_at_ms = unix_ms_i64(outcome.started_at)?;
    let finished_at_ms = unix_ms_i64(outcome.finished_at)?;
    Ok(ValidatedOutcome {
        actual_platform_operation: outcome.actual_platform_operation,
        adapter_version: outcome.adapter_version,
        started_at_ms,
        finished_at_ms,
        stable_status: outcome.stable_status,
        recovery_state: outcome.recovery_state,
        source_postcheck: outcome.source_postcheck,
        destination_postcheck: outcome.destination_postcheck,
        resulting_trash_locator: outcome.resulting_trash_locator,
        platform_result: outcome.platform_result,
        platform_error_domain: outcome.platform_error_domain,
        platform_error_code: outcome.platform_error_code,
        notes: outcome.notes,
    })
}

fn validate_outcome_for_mode(
    requested_mode: RequestedMode,
    outcome: SimulatedOutcome,
) -> Result<ValidatedOutcome, AuditError> {
    validate_outcome_shape(requested_mode, &outcome)?;
    Ok(ValidatedOutcome {
        actual_platform_operation: outcome.actual_platform_operation,
        adapter_version: outcome.adapter_version,
        started_at_ms: unix_ms_i64(outcome.started_at)?,
        finished_at_ms: unix_ms_i64(outcome.finished_at)?,
        stable_status: outcome.stable_status,
        recovery_state: outcome.recovery_state,
        source_postcheck: outcome.source_postcheck,
        destination_postcheck: outcome.destination_postcheck,
        resulting_trash_locator: outcome.resulting_trash_locator,
        platform_result: outcome.platform_result,
        platform_error_domain: outcome.platform_error_domain,
        platform_error_code: outcome.platform_error_code,
        notes: outcome.notes,
    })
}

fn outcome_event(authority: IntentAuthority, validated: ValidatedOutcome) -> OutcomeEvent {
    OutcomeEvent {
        authority,
        actual_platform_operation: validated.actual_platform_operation,
        adapter_version: validated.adapter_version,
        started_at_unix_ms: validated.started_at_ms.to_string(),
        finished_at_unix_ms: validated.finished_at_ms.to_string(),
        stable_status: validated.stable_status,
        recovery_state: validated.recovery_state,
        source_postcheck: validated.source_postcheck,
        destination_postcheck: validated.destination_postcheck,
        resulting_trash_locator: validated.resulting_trash_locator,
        platform_result: validated.platform_result,
        platform_error_domain: validated.platform_error_domain,
        platform_error_code: validated.platform_error_code,
        notes: validated.notes,
    }
}

fn validate_outcome_shape(
    requested_mode: RequestedMode,
    outcome: &SimulatedOutcome,
) -> Result<(), AuditError> {
    validate_nonempty_field(
        &outcome.actual_platform_operation,
        "actual_platform_operation",
        MAX_SHORT_FIELD_BYTES,
    )?;
    validate_nonempty_field(
        &outcome.adapter_version,
        "adapter_version",
        MAX_SHORT_FIELD_BYTES,
    )?;
    validate_observation(&outcome.source_postcheck)?;
    if let Some(observation) = &outcome.destination_postcheck {
        validate_observation(observation)?;
    }
    validate_optional_field(&outcome.resulting_trash_locator, MAX_RESULT_FIELD_BYTES)?;
    validate_optional_field(&outcome.platform_result, MAX_RESULT_FIELD_BYTES)?;
    validate_optional_field(&outcome.platform_error_domain, MAX_SHORT_FIELD_BYTES)?;
    validate_optional_field(&outcome.platform_error_code, MAX_SHORT_FIELD_BYTES)?;
    if outcome.notes.len() > MAX_NOTES
        || outcome.notes.iter().any(|note| note.len() > MAX_NOTE_BYTES)
    {
        return Err(AuditError::RecordTooLarge);
    }
    let started_at_ms = unix_ms_i64(outcome.started_at)?;
    let finished_at_ms = unix_ms_i64(outcome.finished_at)?;
    if finished_at_ms < started_at_ms {
        return Err(AuditError::InvalidOutcome(
            "finished_at precedes started_at",
        ));
    }
    let destination_exists = outcome
        .destination_postcheck
        .as_ref()
        .is_some_and(|destination| destination.exists);
    let has_locator = outcome.resulting_trash_locator.is_some();
    let has_platform_result = outcome.platform_result.is_some();
    let has_error =
        outcome.platform_error_domain.is_some() || outcome.platform_error_code.is_some();
    let expected_operation = operation_for_mode(requested_mode);
    if outcome.actual_platform_operation != expected_operation {
        return Err(AuditError::InvalidOutcome(
            "operation does not match requested mode",
        ));
    }
    match outcome.stable_status {
        StableStatus::TrashSucceededPlatformReported => {
            require_outcome(
                requested_mode == RequestedMode::Trash
                    && outcome.recovery_state == RecoveryState::PlatformTrashReported
                    && !outcome.source_postcheck.exists
                    && has_platform_result
                    && !has_error,
                "contradictory platform-reported Trash success",
            )?;
        }
        StableStatus::TrashSucceededLocationReported => {
            require_outcome(
                requested_mode == RequestedMode::Trash
                    && outcome.recovery_state == RecoveryState::TrashLocationReported
                    && !outcome.source_postcheck.exists
                    && (destination_exists || has_locator)
                    && !has_error,
                "contradictory location-reported Trash success",
            )?;
            if !destination_exists && !has_locator {
                return Err(AuditError::TrashSuccessRequiresDestinationEvidence);
            }
        }
        StableStatus::PermanentDeleteSucceeded => {
            if outcome.source_postcheck.exists {
                return Err(AuditError::SuccessRequiresSourceAbsent);
            }
            if outcome.destination_postcheck.is_some() || has_locator {
                return Err(AuditError::PermanentSuccessMustNotClaimDestination);
            }
            require_outcome(
                requested_mode == RequestedMode::Permanent
                    && outcome.recovery_state == RecoveryState::InapplicablePermanent
                    && has_platform_result
                    && !has_error,
                "contradictory permanent success",
            )?;
        }
        StableStatus::FailedSourceUnchanged => require_outcome(
            outcome.recovery_state == RecoveryState::FailedSourceUnchanged
                && outcome.source_postcheck.exists
                && !destination_exists
                && !has_locator,
            "source-unchanged failure lacks matching observation",
        )?,
        StableStatus::CancelledBeforeAction => require_outcome(
            outcome.recovery_state == RecoveryState::CancelledBeforeAction
                && outcome.source_postcheck.exists
                && !destination_exists
                && !has_locator
                && !has_platform_result
                && !has_error,
            "cancelled-before-action claims platform evidence",
        )?,
        StableStatus::VanishedBeforeAction => require_outcome(
            outcome.recovery_state == RecoveryState::VanishedBeforeAction
                && !outcome.source_postcheck.exists
                && !destination_exists
                && !has_locator
                && !has_platform_result
                && !has_error,
            "vanished-before-action claims platform evidence",
        )?,
        StableStatus::FailedPlatformError | StableStatus::FailedCancelledByPlatform => {
            require_outcome(
                has_error
                    && matches!(
                        outcome.recovery_state,
                        RecoveryState::FailedSourceUnchanged | RecoveryState::Indeterminate
                    ),
                "platform failure lacks native error or recovery state",
            )?
        }
        StableStatus::IndeterminateAfterCrash | StableStatus::IndeterminatePlatformResult => {
            require_outcome(
                outcome.recovery_state == RecoveryState::Indeterminate && !has_locator,
                "indeterminate status carries success semantics",
            )?
        }
    }
    Ok(())
}

fn require_outcome(condition: bool, reason: &'static str) -> Result<(), AuditError> {
    if condition {
        Ok(())
    } else {
        Err(AuditError::InvalidOutcome(reason))
    }
}

fn validate_observation(observation: &Observation) -> Result<(), AuditError> {
    validate_optional_field(&observation.identity, MAX_RESULT_FIELD_BYTES)?;
    if !observation.exists && observation.identity.is_some() {
        return Err(AuditError::InvalidOutcome(
            "absent observation carries identity",
        ));
    }
    Ok(())
}

fn classify_observation(
    mode: RequestedMode,
    observation: &RecoveryObservation,
) -> Result<(RecoveryDisposition, String), AuditError> {
    match observation {
        RecoveryObservation::SourceStillPresent { source } if source.exists => Ok((
            RecoveryDisposition::Reserved,
            "source still present; reserved intent was not replayed".to_string(),
        )),
        RecoveryObservation::SourceAbsentDestinationConfirmed { destination }
            if mode == RequestedMode::Trash && destination.exists =>
        {
            Ok((
                RecoveryDisposition::Pending,
                "source absent and Trash destination confirmed".to_string(),
            ))
        }
        RecoveryObservation::SourceAbsentDestinationConfirmed { destination }
            if destination.exists =>
        {
            Ok((
                RecoveryDisposition::Indeterminate,
                "destination evidence cannot establish permanent-operation semantics".to_string(),
            ))
        }
        RecoveryObservation::SourceAbsentDestinationUnconfirmed | RecoveryObservation::Unknown => {
            Ok((
                RecoveryDisposition::Indeterminate,
                "source/destination facts remain indeterminate".to_string(),
            ))
        }
        _ => Err(AuditError::InvalidRecoveryObservation),
    }
}

fn terminal_for_disposition(disposition: RecoveryDisposition) -> &'static str {
    match disposition {
        RecoveryDisposition::Pending => "classified_pending",
        RecoveryDisposition::Reserved => "classified_reserved",
        RecoveryDisposition::Indeterminate => "classified_indeterminate",
    }
}
fn disposition_db(disposition: RecoveryDisposition) -> &'static str {
    match disposition {
        RecoveryDisposition::Pending => "pending",
        RecoveryDisposition::Reserved => "reserved",
        RecoveryDisposition::Indeterminate => "indeterminate",
    }
}
fn risk_db(risk: RiskTier) -> &'static str {
    match risk {
        RiskTier::R1 => "r1",
        RiskTier::R2 => "r2",
        RiskTier::R3 => "r3",
        RiskTier::R4 => "r4",
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, AuditError> {
    serde_jcs::to_string(value)
        .map_err(|error| AuditError::Io(std::io::Error::other(error.to_string())))
}
fn unix_ms_i64(time: SystemTime) -> Result<i64, AuditError> {
    i64::try_from(
        time.duration_since(UNIX_EPOCH)
            .map_err(|_| AuditError::InvalidClock)?
            .as_millis(),
    )
    .map_err(|_| AuditError::InvalidClock)
}
fn monotonic_elapsed_ns() -> u128 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
}

fn random_id(transaction: &Transaction<'_>, label: &str) -> Result<String, AuditError> {
    let random: Vec<u8> = transaction.query_row("SELECT randomblob(32)", [], |row| row.get(0))?;
    Ok(format!("{label}:{}", hex_encode(&random)))
}

fn validate_stable_id(value: &str, field: &'static str) -> Result<(), AuditError> {
    if (8..=MAX_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
    {
        Ok(())
    } else {
        Err(AuditError::InvalidStableId { field })
    }
}
fn validate_bounded_field(
    value: &str,
    _field: &'static str,
    maximum: usize,
) -> Result<(), AuditError> {
    if value.len() <= maximum && !value.chars().any(|character| character == char::from(0)) {
        Ok(())
    } else {
        Err(AuditError::RecordTooLarge)
    }
}
fn validate_nonempty_field(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), AuditError> {
    validate_bounded_field(value, field, maximum)?;
    if value.trim().is_empty() {
        Err(AuditError::InvalidOutcome(field))
    } else {
        Ok(())
    }
}
fn validate_optional_field(value: &Option<String>, maximum: usize) -> Result<(), AuditError> {
    if let Some(value) = value {
        validate_nonempty_field(value, "optional outcome field", maximum)?;
    }
    Ok(())
}
fn file_len_if_exists(path: &Path) -> Result<u64, AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(AuditError::SymlinkRejected(path.display().to_string()));
            }
            Ok(metadata.len())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn hash_native_path(path: &Path) -> Result<PathHash, AuditError> {
    if !path.is_absolute() {
        return Err(AuditError::UnsafeStateDir(path.display().to_string()));
    }
    let mut hasher = Sha256::new();
    hasher.update(PATH_HASH_DOMAIN);
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in path.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
    }
    PathHash::new(format!("sha256:{}", hex_encode(&hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use tempfile::TempDir;

    fn store() -> (TempDir, AuditStore) {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir(&root).unwrap();
        let store = AuditStore::open(&root).unwrap();
        (temp, store)
    }

    fn binding(index: u8, mode: RequestedMode) -> AuthorizationBinding {
        let item = ItemId::new(format!("item-{index:02}-sqlite")).unwrap();
        let action = ActionId::new(format!("action-{index:02}-sqlite")).unwrap();
        let mut items = BTreeSet::new();
        items.insert(item.clone());
        let mut actions = BTreeSet::new();
        actions.insert(action.clone());
        let mut item_by_action = BTreeMap::new();
        item_by_action.insert(action.clone(), item);
        let mut risk_by_action = BTreeMap::new();
        risk_by_action.insert(
            action,
            if mode == RequestedMode::Permanent {
                RiskTier::R4
            } else {
                RiskTier::R2
            },
        );
        AuthorizationBinding {
            authorization_id: AuthorizationId::new(format!("auth-{index:02}-sqlite")).unwrap(),
            authorization_source: AuthorizationSource::DeterministicSimulation,
            batch_id: BatchId::new(format!("batch-{index:02}-sqlite")).unwrap(),
            plan_id: PlanId::new(format!("plan-{index:02}-sqlite")).unwrap(),
            plan_digest: DigestString::new(format!("plan-digest-{index:02}")).unwrap(),
            requested_mode: mode,
            item_ids: items,
            action_ids: actions,
            action_count: 1,
            item_by_action,
            risk_by_action,
            policy_version: "policy-v1".to_string(),
            policy_digest: DigestString::new(format!("policy-digest-{index:02}")).unwrap(),
            protected_anchor_snapshot_digest: DigestString::new(format!(
                "anchor-digest-{index:02}"
            ))
            .unwrap(),
            adapter_capabilities_digest: DigestString::new(format!("adapter-digest-{index:02}"))
                .unwrap(),
            cleaner_set_digest: DigestString::new(format!("cleaner-digest-{index:02}")).unwrap(),
            host_instance_id: HostId::new(format!("host-{index:02}-sqlite")).unwrap(),
            user_identity: UserId::new(format!("user-{index:02}-sqlite")).unwrap(),
            workflow_session: SessionId::new(format!("session-{index:02}-sqlite")).unwrap(),
        }
    }

    fn register(store: &AuditStore, binding: &AuthorizationBinding) {
        store
            .register_authorization(RegisterAuthorization {
                binding: binding.clone(),
            })
            .unwrap();
    }

    fn reserve(
        store: &AuditStore,
        claim: &ClaimedExecution,
        binding: &AuthorizationBinding,
    ) -> DurableIntentToken {
        store
            .reserve_intent(
                claim,
                IntentRequest {
                    item_id: binding.item_ids.iter().next().unwrap().clone(),
                    action_id: binding.action_ids.iter().next().unwrap().clone(),
                    source_path_hash: PathHash::new("source-path-sqlite").unwrap(),
                    before_revalidation_digest: DigestString::new("revalidation-sqlite").unwrap(),
                },
            )
            .unwrap()
    }

    fn permanent_success() -> SimulatedOutcome {
        SimulatedOutcome {
            actual_platform_operation: "simulated_permanent_delete".to_string(),
            adapter_version: "adapter-v1".to_string(),
            started_at: UNIX_EPOCH + Duration::from_secs(1),
            finished_at: UNIX_EPOCH + Duration::from_secs(2),
            stable_status: StableStatus::PermanentDeleteSucceeded,
            recovery_state: RecoveryState::InapplicablePermanent,
            source_postcheck: Observation {
                exists: false,
                identity: None,
            },
            destination_postcheck: None,
            resulting_trash_locator: None,
            platform_result: Some("ok".to_string()),
            platform_error_domain: None,
            platform_error_code: None,
            notes: vec![],
        }
    }

    struct FixedObserver(RecoveryObservation);
    impl RecoveryObserver for FixedObserver {
        fn observe(&self, _: &RecoveryIntentView) -> Result<RecoveryObservation, AuditError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn sqlite_configuration_and_every_mutation_is_chained() {
        let (_temp, store) = store();
        let binding = binding(1, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let token = reserve(&store, &claim, &binding);
        store
            .record_outcome(&claim, &token, permanent_success())
            .unwrap();
        store.consume_execution(&claim).unwrap();
        let summary = store.verify_integrity().unwrap();
        assert_eq!(summary.latest_sequence, 5);
        let connection = store.connection().unwrap();
        assert_eq!(
            connection
                .pragma_query_value::<String, _>(None, "journal_mode", |row| row.get(0))
                .unwrap()
                .to_ascii_lowercase(),
            "wal"
        );
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "synchronous", |row| row.get(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .pragma_query_value::<i64, _>(None, "mmap_size", |row| row.get(0))
                .unwrap(),
            0
        );
        assert_eq!(
            fs::read_dir(&store.root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("audit"))
                .count(),
            4
        );
    }

    #[test]
    fn claim_lock_lives_for_the_entire_session_and_recovery_fences_after_drop() {
        let (_temp, store) = store();
        let binding = binding(2, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        assert!(matches!(
            store.claim_recovery(&binding.authorization_id, &binding.plan_digest),
            Err(AuditError::ConcurrentWriterDenied)
        ));
        let fence = claim.fence_epoch();
        drop(claim);
        let recovery = store
            .claim_recovery(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        assert!(recovery.fence_epoch() > fence);
    }

    #[test]
    fn exact_pairing_and_duplicate_action_are_rejected() {
        let (_temp, store) = store();
        let mut invalid_binding = binding(3, RequestedMode::Permanent);
        let second_item = ItemId::new("item-second-sqlite").unwrap();
        invalid_binding.item_ids.insert(second_item.clone());
        assert!(matches!(
            store.register_authorization(RegisterAuthorization {
                binding: invalid_binding
            }),
            Err(AuditError::AuthorizationBindingMismatch)
        ));

        let binding = binding(4, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let request = IntentRequest {
            item_id: binding.item_ids.iter().next().unwrap().clone(),
            action_id: binding.action_ids.iter().next().unwrap().clone(),
            source_path_hash: PathHash::new("path-first-sqlite").unwrap(),
            before_revalidation_digest: DigestString::new("reval-first-sqlite").unwrap(),
        };
        store.reserve_intent(&claim, request.clone()).unwrap();
        assert!(matches!(
            store.reserve_intent(&claim, request),
            Err(AuditError::ActionAlreadyReserved(_))
        ));
    }

    #[test]
    fn mismatched_token_and_contradictory_outcome_are_rejected() {
        let (_temp, store) = store();
        let first = binding(5, RequestedMode::Permanent);
        register(&store, &first);
        let first_claim = store
            .claim_execution(&first.authorization_id, &first.plan_digest)
            .unwrap();
        let token = reserve(&store, &first_claim, &first);
        let mut contradictory = permanent_success();
        contradictory.finished_at = UNIX_EPOCH;
        assert!(matches!(
            store.record_outcome(&first_claim, &token, contradictory),
            Err(AuditError::InvalidClock | AuditError::InvalidOutcome(_))
        ));
        drop(first_claim);

        let other_temp = TempDir::new().unwrap();
        let other_store = AuditStore::open(other_temp.path().join("audit")).unwrap();
        let second = binding(6, RequestedMode::Permanent);
        register(&other_store, &second);
        let second_claim = other_store
            .claim_execution(&second.authorization_id, &second.plan_digest)
            .unwrap();
        assert!(matches!(
            other_store.record_outcome(&second_claim, &token, permanent_success()),
            Err(AuditError::AuthorizationBindingMismatch)
        ));
        drop(second_claim);
    }

    #[test]
    fn recovery_is_idempotent_and_reserved_or_indeterminate_blocks_consume() {
        let (_temp, store) = store();
        let binding = binding(7, RequestedMode::Trash);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        reserve(&store, &claim, &binding);
        drop(claim);
        let recovery = store
            .claim_recovery(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let first = store
            .classify_recovery(&recovery, &FixedObserver(RecoveryObservation::Unknown))
            .unwrap();
        let second = store
            .classify_recovery(
                &recovery,
                &FixedObserver(RecoveryObservation::SourceStillPresent {
                    source: Observation {
                        exists: true,
                        identity: Some("same".to_string()),
                    },
                }),
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first[0].disposition, RecoveryDisposition::Indeterminate);
        assert!(matches!(
            store.consume_execution(&recovery),
            Err(AuditError::UnresolvedIntentsRemain)
        ));
    }

    #[test]
    fn pending_recovery_requires_an_explicit_recovery_outcome_before_consume() {
        let (_temp, store) = store();
        let binding = binding(9, RequestedMode::Trash);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let token = reserve(&store, &claim, &binding);
        let attempt_id = token.attempt_id().clone();
        drop(token);
        drop(claim);
        let recovery = store
            .claim_recovery(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let records = store
            .classify_recovery(
                &recovery,
                &FixedObserver(RecoveryObservation::SourceAbsentDestinationConfirmed {
                    destination: Observation {
                        exists: true,
                        identity: Some("trash-object".to_string()),
                    },
                }),
            )
            .unwrap();
        assert_eq!(records[0].disposition, RecoveryDisposition::Pending);
        assert!(matches!(
            store.consume_execution(&recovery),
            Err(AuditError::UnresolvedIntentsRemain)
        ));
        store
            .record_recovery_outcome(
                &recovery,
                &attempt_id,
                SimulatedOutcome::trash_success(
                    "adapter-v1",
                    UNIX_EPOCH + Duration::from_secs(1),
                    UNIX_EPOCH + Duration::from_secs(2),
                    Observation {
                        exists: false,
                        identity: None,
                    },
                    Observation {
                        exists: true,
                        identity: Some("trash-object".to_string()),
                    },
                    Some("trash:locator".to_string()),
                    "ok",
                    vec![],
                )
                .unwrap(),
            )
            .unwrap();
        store.consume_execution(&recovery).unwrap();
    }

    #[test]
    fn projection_snapshot_reports_terminal_state_without_reconciliation() {
        let (_temp, store) = store();
        let binding = binding(16, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let token = reserve(&store, &claim, &binding);
        store
            .record_outcome(&claim, &token, permanent_success())
            .unwrap();
        store.consume_execution(&claim).unwrap();

        let snapshot = store.projection_snapshot().unwrap();
        assert_eq!(snapshot.batches.len(), 1);
        let batch = &snapshot.batches[0];
        assert_eq!(batch.batch_id, binding.batch_id.as_str());
        assert_eq!(batch.state, AuditProjectionState::Terminal);
        assert!(!batch.needs_reconciliation);
        let item = &batch.items[0];
        assert_eq!(item.state, AuditProjectionState::Terminal);
        assert!(!item.needs_reconciliation);
        let authorization = &item.authorizations[0];
        assert_eq!(authorization.state, AuditProjectionState::Terminal);
        let action = &authorization.actions[0];
        assert_eq!(action.state, AuditProjectionState::Terminal);
        assert!(!action.needs_reconciliation);
        assert_eq!(
            action.terminal_outcome.as_ref().unwrap().stable_status,
            AuditStableStatus::PermanentDeleteSucceeded
        );
    }

    #[test]
    fn projection_snapshot_distinguishes_pending_and_indeterminate() {
        let (_temp, store) = store();

        let pending_binding = binding(17, RequestedMode::Trash);
        register(&store, &pending_binding);
        let pending_claim = store
            .claim_execution(
                &pending_binding.authorization_id,
                &pending_binding.plan_digest,
            )
            .unwrap();
        reserve(&store, &pending_claim, &pending_binding);
        drop(pending_claim);
        let pending_recovery = store
            .claim_recovery(
                &pending_binding.authorization_id,
                &pending_binding.plan_digest,
            )
            .unwrap();
        store
            .classify_recovery(
                &pending_recovery,
                &FixedObserver(RecoveryObservation::SourceAbsentDestinationConfirmed {
                    destination: Observation {
                        exists: true,
                        identity: Some("trash-object".to_string()),
                    },
                }),
            )
            .unwrap();
        drop(pending_recovery);

        let indeterminate_binding = binding(18, RequestedMode::Trash);
        register(&store, &indeterminate_binding);
        let indeterminate_claim = store
            .claim_execution(
                &indeterminate_binding.authorization_id,
                &indeterminate_binding.plan_digest,
            )
            .unwrap();
        reserve(&store, &indeterminate_claim, &indeterminate_binding);
        drop(indeterminate_claim);
        let indeterminate_recovery = store
            .claim_recovery(
                &indeterminate_binding.authorization_id,
                &indeterminate_binding.plan_digest,
            )
            .unwrap();
        store
            .classify_recovery(
                &indeterminate_recovery,
                &FixedObserver(RecoveryObservation::Unknown),
            )
            .unwrap();

        let snapshot = store.projection_snapshot().unwrap();
        assert_eq!(snapshot.batches.len(), 2);
        let pending_batch = snapshot
            .batches
            .iter()
            .find(|batch| batch.batch_id == pending_binding.batch_id.as_str())
            .unwrap();
        assert_eq!(pending_batch.state, AuditProjectionState::Pending);
        assert!(pending_batch.needs_reconciliation);
        assert_eq!(
            pending_batch.items[0].authorizations[0].actions[0].recovery_disposition,
            Some(AuditRecoveryDisposition::Pending)
        );

        let indeterminate_batch = snapshot
            .batches
            .iter()
            .find(|batch| batch.batch_id == indeterminate_binding.batch_id.as_str())
            .unwrap();
        assert_eq!(
            indeterminate_batch.state,
            AuditProjectionState::Indeterminate
        );
        assert!(indeterminate_batch.needs_reconciliation);
        assert_eq!(
            indeterminate_batch.items[0].authorizations[0].actions[0].recovery_disposition,
            Some(AuditRecoveryDisposition::Indeterminate)
        );
    }

    #[test]
    fn projection_snapshot_returns_explicit_corruption_error() {
        let (_temp, store) = store();
        let binding = binding(19, RequestedMode::Permanent);
        register(&store, &binding);
        {
            let connection = store.connection().unwrap();
            connection
                .execute(
                    "UPDATE authorizations SET plan_digest='forged-digest' WHERE authorization_id=?1",
                    [binding.authorization_id.as_str()],
                )
                .unwrap();
        }
        let error = store.projection_snapshot().unwrap_err();
        assert!(matches!(error, ProjectionError::Corruption(_)));
    }

    #[test]
    fn projection_snapshot_classifies_invalid_database_header_as_corruption() {
        let (_temp, store) = store();
        let connection = store.connection().unwrap();
        connection.pragma_update(None, "application_id", 0).unwrap();
        drop(connection);

        let error = store.projection_snapshot().unwrap_err();
        assert!(matches!(error, ProjectionError::Corruption(_)));
    }

    #[test]
    fn projection_snapshot_uses_authorized_for_registered_only_actions() {
        let (_temp, store) = store();
        let binding = binding(20, RequestedMode::Permanent);
        register(&store, &binding);

        let snapshot = store.projection_snapshot().unwrap();
        let batch = &snapshot.batches[0];
        assert_eq!(batch.state, AuditProjectionState::Authorized);
        assert!(!batch.needs_reconciliation);
        let item = &batch.items[0];
        assert_eq!(item.state, AuditProjectionState::Authorized);
        let authorization = &item.authorizations[0];
        assert_eq!(authorization.state, AuditProjectionState::Authorized);
        let action = &authorization.actions[0];
        assert_eq!(action.state, AuditProjectionState::Authorized);
        assert_eq!(action.attempt_id, None);
        assert!(!action.needs_reconciliation);
    }

    #[test]
    fn projection_snapshot_indeterminate_dominates_pending_and_preserves_shared_item_authorizations()
     {
        let (_temp, store) = store();
        let shared_item = ItemId::new("shared-item-sqlite").unwrap();

        let mut first = binding(21, RequestedMode::Permanent);
        let first_action = first.action_ids.iter().next().unwrap().clone();
        first.item_ids = BTreeSet::from([shared_item.clone()]);
        first.item_by_action = BTreeMap::from([(first_action.clone(), shared_item.clone())]);
        register(&store, &first);

        let mut second = binding(22, RequestedMode::Permanent);
        let second_action = second.action_ids.iter().next().unwrap().clone();
        second.batch_id = first.batch_id.clone();
        second.item_ids = BTreeSet::from([shared_item.clone()]);
        second.item_by_action = BTreeMap::from([(second_action.clone(), shared_item.clone())]);
        register(&store, &second);

        let first_claim = store
            .claim_execution(&first.authorization_id, &first.plan_digest)
            .unwrap();
        let first_token = reserve(&store, &first_claim, &first);
        store
            .record_outcome(
                &first_claim,
                &first_token,
                SimulatedOutcome::indeterminate_after_crash(
                    RequestedMode::Permanent,
                    "adapter-v1",
                    UNIX_EPOCH + Duration::from_secs(1),
                    UNIX_EPOCH + Duration::from_secs(2),
                    Observation {
                        exists: false,
                        identity: None,
                    },
                    vec![],
                )
                .unwrap(),
            )
            .unwrap();
        drop(first_claim);

        let second_claim = store
            .claim_execution(&second.authorization_id, &second.plan_digest)
            .unwrap();
        reserve(&store, &second_claim, &second);

        let snapshot = store.projection_snapshot().unwrap();
        let batch = snapshot
            .batches
            .iter()
            .find(|batch| batch.batch_id == first.batch_id.as_str())
            .unwrap();
        assert_eq!(batch.state, AuditProjectionState::Indeterminate);
        assert!(batch.needs_reconciliation);
        assert_eq!(batch.items.len(), 1);
        let item = &batch.items[0];
        assert_eq!(item.item_id, shared_item.as_str());
        assert_eq!(item.state, AuditProjectionState::Indeterminate);
        assert_eq!(item.authorizations.len(), 2);

        let first_auth = item
            .authorizations
            .iter()
            .find(|auth| auth.authorization_id == first.authorization_id.as_str())
            .unwrap();
        assert_eq!(first_auth.state, AuditProjectionState::Indeterminate);
        assert!(first_auth.actions[0].needs_reconciliation);
        assert_eq!(
            first_auth.actions[0]
                .terminal_outcome
                .as_ref()
                .unwrap()
                .recovery_state,
            AuditOutcomeRecoveryState::Indeterminate
        );

        let second_auth = item
            .authorizations
            .iter()
            .find(|auth| auth.authorization_id == second.authorization_id.as_str())
            .unwrap();
        assert_eq!(second_auth.state, AuditProjectionState::Pending);
        assert!(second_auth.needs_reconciliation);
    }

    #[test]
    fn projection_only_tamper_is_rejected_by_event_replay() {
        let (_temp, store) = store();
        let binding = binding(10, RequestedMode::Permanent);
        register(&store, &binding);
        {
            let connection = store.connection().unwrap();
            connection.execute("UPDATE authorizations SET plan_digest='forged-digest' WHERE authorization_id=?1", [binding.authorization_id.as_str()]).unwrap();
        }
        assert!(matches!(
            store.verify_integrity(),
            Err(AuditError::HeadMismatch)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_sidecar_is_rejected_before_connection_open() {
        use std::os::unix::fs::symlink;
        let (temp, store) = store();
        drop(store);
        let wal = temp.path().join("external-wal");
        File::create(&wal).unwrap();
        symlink(
            &wal,
            temp.path()
                .join("audit")
                .join(format!("{DATABASE_FILE}-wal")),
        )
        .unwrap();
        assert!(matches!(
            AuditStore::open(temp.path().join("audit")),
            Err(AuditError::SymlinkRejected(_))
        ));
    }

    #[test]
    fn token_requires_the_live_claim_and_current_reserved_fence() {
        let (_temp, store) = store();
        let binding = binding(11, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let token = reserve(&store, &claim, &binding);
        assert!(token.validate_current_process().is_ok());
        drop(claim);
        assert!(matches!(
            token.validate_current_process(),
            Err(AuditError::ClaimNotActive)
        ));
    }

    #[test]
    fn token_remains_send_and_sync_while_claim_remains_send() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<DurableIntentToken>();
        assert_sync::<DurableIntentToken>();
        assert_send::<ClaimedExecution>();
    }

    #[test]
    fn claim_is_not_sync() {
        trait AmbiguousIfSync<Marker> {
            fn marker() {}
        }
        struct Implemented;
        impl<T: ?Sized> AmbiguousIfSync<()> for T {}
        impl<T: ?Sized + Sync> AmbiguousIfSync<Implemented> for T {}
        let _ = <ClaimedExecution as AmbiguousIfSync<_>>::marker;
    }

    #[test]
    fn token_is_spent_by_outcome_while_claim_stays_live() {
        let (_temp, store) = store();
        let binding = binding(12, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let token = reserve(&store, &claim, &binding);
        assert!(token.validate_current_process().is_ok());
        store
            .record_outcome(&claim, &token, permanent_success())
            .unwrap();
        assert!(matches!(
            token.validate_current_process(),
            Err(AuditError::FenceEpochMismatch)
        ));
    }

    #[test]
    fn cloned_store_cannot_claim_while_same_process_session_is_active() {
        let (_temp, store) = store();
        let cloned = store.clone();
        let binding = binding(13, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        assert!(matches!(
            cloned.claim_recovery(&binding.authorization_id, &binding.plan_digest),
            Err(AuditError::ConcurrentWriterDenied)
        ));
        drop(claim);
        assert!(
            cloned
                .claim_recovery(&binding.authorization_id, &binding.plan_digest)
                .is_ok()
        );
    }

    #[test]
    fn recovery_observer_runs_outside_the_claim_mutation_mutex() {
        struct ReentrantObserver<'a> {
            store: &'a AuditStore,
            claim: &'a ClaimedExecution,
        }
        impl RecoveryObserver for ReentrantObserver<'_> {
            fn observe(&self, _: &RecoveryIntentView) -> Result<RecoveryObservation, AuditError> {
                let unresolved = self.store.unresolved_recovery_intents(self.claim)?;
                assert_eq!(unresolved.len(), 1);
                Ok(RecoveryObservation::Unknown)
            }
        }
        let (_temp, store) = store();
        let binding = binding(14, RequestedMode::Trash);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        reserve(&store, &claim, &binding);
        drop(claim);
        let recovery = store
            .claim_recovery(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let records = store
            .classify_recovery(
                &recovery,
                &ReentrantObserver {
                    store: &store,
                    claim: &recovery,
                },
            )
            .unwrap();
        assert_eq!(records[0].disposition, RecoveryDisposition::Indeterminate);
    }

    #[cfg(unix)]
    #[test]
    fn manually_unlocked_claim_cannot_validate_token() {
        let (_temp, store) = store();
        let binding = binding(15, RequestedMode::Permanent);
        register(&store, &binding);
        let claim = store
            .claim_execution(&binding.authorization_id, &binding.plan_digest)
            .unwrap();
        let token = reserve(&store, &claim, &binding);
        {
            let guard = claim.live_claim.lock_file.lock().unwrap();
            FileExt::unlock(guard.as_ref().unwrap()).unwrap();
        }
        assert!(matches!(
            token.validate_current_process(),
            Err(AuditError::ClaimNotActive)
        ));
    }

    #[test]
    fn event_tamper_and_sqlite_corruption_are_detected() {
        let (_temp, store) = store();
        let binding = binding(8, RequestedMode::Permanent);
        register(&store, &binding);
        {
            let connection = store.connection().unwrap();
            connection.execute_batch("DROP TRIGGER audit_events_no_update; UPDATE audit_events SET digest='sha256:tampered' WHERE sequence=1;").unwrap();
        }
        assert!(matches!(
            store.verify_integrity(),
            Err(AuditError::JournalTampered { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_database_and_non_private_existing_directory_are_rejected() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let external = temp.path().join("external");
        File::create(&external).unwrap();
        symlink(&external, root.join(DATABASE_FILE)).unwrap();
        assert!(matches!(
            AuditStore::open(&root),
            Err(AuditError::SymlinkRejected(_))
        ));

        let broad = temp.path().join("broad");
        fs::DirBuilder::new().mode(0o755).create(&broad).unwrap();
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            AuditStore::open(&broad),
            Err(AuditError::StateDirNotPrivate(_))
        ));
    }
}
