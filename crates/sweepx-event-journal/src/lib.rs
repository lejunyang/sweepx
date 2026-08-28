//! Unix-only crash-consistent event journal substrate.
//!
//! The hash chain detects accidental corruption and inconsistent partial state. It is deliberately
//! unkeyed and therefore is not authentication against a same-user or offline writer. The public
//! Core exposes Linux-only NDJSON replay for completed persisted streams; live scan NDJSON remains
//! disabled until a runtime-qualified live event sink exists.
//! The 32 MiB size value is an admission target backed by SQLite page limits and conservative
//! pre-append headroom, not a wall-clock or exact post-commit byte guarantee. This foundation uses
//! replay sessions verify one bounded snapshot up front and page only over that immutable snapshot.
//! They do not follow later appends and therefore do not expose live streaming. Other journal
//! operations still verify the durable state before acting, and this crate does not yet claim the
//! design's one-second runtime gate.

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(any(target_os = "linux", all(test, target_os = "linux")))]
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::Path;
#[cfg(any(target_os = "linux", all(test, target_os = "linux")))]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use fs2::FileExt;
#[cfg(target_os = "linux")]
use getrandom::fill as fill_random;
#[cfg(target_os = "linux")]
use rusqlite::Connection;
#[cfg(target_os = "linux")]
use rusqlite::config::DbConfig;
#[cfg(target_os = "linux")]
use rusqlite::{OpenFlags, Transaction, TransactionBehavior, params};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use sweepx_protocol::{EventEnvelope, TerminalEventExpectation};
#[cfg(target_os = "linux")]
use sweepx_protocol::{EventStreamValidationError, validate_durable_event_stream};
use thiserror::Error;
#[cfg(target_os = "linux")]
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[cfg(target_os = "linux")]
const LOCK_FILE: &str = "stream.lock";
#[cfg(target_os = "linux")]
const DATABASE_FILE: &str = "journal.db";
#[cfg(target_os = "linux")]
const SCHEMA_VERSION: &str = "sweepx.event_journal.sqlite.v1";
#[cfg(target_os = "linux")]
const APPLICATION_ID: i64 = 0x5357_584a;
#[cfg(target_os = "linux")]
const USER_VERSION: i64 = 1;
#[cfg(target_os = "linux")]
const PAGE_SIZE: i64 = 4096;
#[cfg(target_os = "linux")]
const MAX_PAGE_COUNT: i64 = 6912;
#[cfg(target_os = "linux")]
const MAX_DATABASE_BYTES: u64 = PAGE_SIZE as u64 * MAX_PAGE_COUNT as u64;
#[cfg(target_os = "linux")]
const MAX_WAL_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_APPEND_RESERVE_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_BATCH_STORAGE_OVERHEAD_PER_EVENT: usize = 1024;
#[cfg(target_os = "linux")]
const MAX_EVENT_BYTES: usize = 256 * 1024;
#[cfg(target_os = "linux")]
const MAX_REPLAY_DECODED_BYTES: usize = 192 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = sweepx_protocol::MAX_EVENT_CURSOR_BYTES;
#[cfg(target_os = "linux")]
const MAX_EVENTS: i64 = 50_000;
#[cfg(target_os = "linux")]
const RECORD_DOMAIN: &[u8] = b"SweepX durable event journal v1\0";

#[derive(Debug, Clone, PartialEq)]
pub struct ReplayBatch {
    pub events: Vec<EventEnvelope>,
    pub reset_required: bool,
    pub next_cursor: Option<String>,
}

/// An immutable, fully verified view of one bounded journal generation.
///
/// Opening a session verifies the complete durable journal once. Page reads then operate only on
/// that verified snapshot: they never observe later appends, wait for events, or poll for changes.
#[derive(Debug)]
pub struct ReplaySession {
    events: Vec<EventEnvelope>,
    #[cfg(target_os = "linux")]
    cursor_offsets: BTreeMap<String, usize>,
    integrity: JournalIntegrity,
    final_snapshot: Option<FinalSnapshotMetadata>,
}

#[derive(Debug)]
pub enum OwnedReplay {
    ResetRequired { next_cursor: Option<String> },
    Pages(ReplayPages),
}

#[derive(Debug)]
pub struct ReplayPages {
    events: std::vec::IntoIter<EventEnvelope>,
    limit: usize,
}

impl Iterator for ReplayPages {
    type Item = ReplayBatch;

    fn next(&mut self) -> Option<Self::Item> {
        if self.events.len() == 0 {
            return None;
        }
        let mut events = Vec::with_capacity(self.limit.min(self.events.len()));
        for _ in 0..self.limit {
            let Some(event) = self.events.next() else {
                break;
            };
            events.push(event);
        }
        let next_cursor = events.last().map(|event| event.cursor.clone());
        Some(ReplayBatch {
            events,
            reset_required: false,
            next_cursor,
        })
    }
}

impl ReplaySession {
    /// Returns at most `limit` verified events after `cursor`.
    ///
    /// `limit` must be in `1..=1024`. An unknown, well-formed cursor requests a reset to this
    /// session's latest verified cursor. The session remains frozen even if its journal is later
    /// appended to.
    pub fn replay_from_cursor(
        &self,
        cursor: Option<&DurableCursor>,
        limit: usize,
    ) -> Result<ReplayBatch, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            let _ = cursor;
            let _ = limit;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            if !(1..=1024).contains(&limit) {
                return Err(JournalError::InvalidReplayLimit);
            }

            let start_offset = match cursor {
                None => 0,
                Some(cursor) => {
                    let Some(offset) = self.cursor_offsets.get(cursor.as_str()).copied() else {
                        return Ok(ReplayBatch {
                            events: Vec::new(),
                            reset_required: true,
                            next_cursor: self.integrity.latest_cursor.clone(),
                        });
                    };
                    offset
                }
            };
            let end_offset = start_offset.saturating_add(limit).min(self.events.len());
            let events = self.events[start_offset..end_offset].to_vec();
            let next_cursor = events.last().map(|event| event.cursor.clone());

            Ok(ReplayBatch {
                events,
                reset_required: false,
                next_cursor,
            })
        }
    }

    /// Consumes this verified session into bounded owned pages without cloning event payloads.
    pub fn into_replay_pages(
        self,
        cursor: Option<&DurableCursor>,
    ) -> Result<OwnedReplay, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            let _ = cursor;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let start_offset = match cursor {
                None => 0,
                Some(cursor) => {
                    let Some(offset) = self.cursor_offsets.get(cursor.as_str()).copied() else {
                        return Ok(OwnedReplay::ResetRequired {
                            next_cursor: self.integrity.latest_cursor.clone(),
                        });
                    };
                    offset
                }
            };
            let mut events = self.events.into_iter();
            for _ in 0..start_offset {
                let _ = events.next();
            }
            Ok(OwnedReplay::Pages(ReplayPages {
                events,
                limit: 1024,
            }))
        }
    }

    /// The number of events covered by the session's full integrity verification.
    pub fn verified_event_count(&self) -> usize {
        self.events.len()
    }

    /// The latest cursor in the immutable verified snapshot, if it is non-empty.
    pub fn latest_cursor(&self) -> Option<&str> {
        self.integrity.latest_cursor.as_deref()
    }

    /// Integrity facts frozen by the same transaction that supplied replay events and metadata.
    pub fn integrity(&self) -> &JournalIntegrity {
        &self.integrity
    }

    /// The terminal snapshot frozen by the session's verification transaction, when complete.
    pub fn final_snapshot(&self) -> Option<&FinalSnapshotMetadata> {
        self.final_snapshot.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalIntegrity {
    pub event_count: u64,
    pub terminal_sequence: Option<u64>,
    pub latest_sequence: u64,
    pub latest_cursor: Option<String>,
    pub last_durable_sequence: u64,
    pub snapshot_digest: Option<String>,
    decoded_event_bytes: usize,
    cursor_index_bytes: usize,
    latest_record_digest: Option<String>,
    latest_emitted_at_ns: Option<i128>,
    latest_monotonic_offset_ns: Option<u128>,
    generation_nonce: String,
}

impl JournalIntegrity {
    pub fn has_terminal_snapshot(&self) -> bool {
        self.terminal_sequence.is_some() && self.snapshot_digest.is_some()
    }
}

impl JournalIntegrity {
    pub fn next_position(
        &self,
        stream_id: &str,
        operation_id: &str,
        durable: bool,
    ) -> Result<JournalAppendPosition, JournalError> {
        if self.terminal_sequence.is_some() {
            return Err(JournalError::AlreadyTerminal);
        }
        #[cfg(target_os = "linux")]
        {
            let sequence = self
                .latest_sequence
                .checked_add(1)
                .ok_or(JournalError::EventLimitExceeded)?;
            if sequence > MAX_EVENTS as u64 {
                return Err(JournalError::EventLimitExceeded);
            }
            let basis = self.latest_record_digest.as_deref().unwrap_or("genesis");
            Ok(JournalAppendPosition {
                sequence,
                cursor: DurableCursor(next_durable_cursor(
                    stream_id,
                    operation_id,
                    sequence,
                    &self.generation_nonce,
                    basis,
                )),
                last_durable_sequence: if durable {
                    sequence
                } else {
                    self.last_durable_sequence
                },
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream_id;
            let _ = operation_id;
            let _ = durable;
            Err(JournalError::Unsupported)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalAppendPosition {
    pub sequence: u64,
    pub cursor: DurableCursor,
    pub last_durable_sequence: u64,
}

impl JournalAppendPosition {
    pub fn apply_to(&self, event: &mut EventEnvelope) {
        event.sequence = u128::from(self.sequence).into();
        event.cursor = self.cursor.as_str().to_string();
        event.checkpoint.durable = true;
        event.checkpoint.last_durable_sequence = u128::from(self.last_durable_sequence).into();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalSnapshotMetadata {
    snapshot_digest: String,
    canonical_snapshot: Vec<u8>,
    terminal: TerminalEventExpectation,
    operation_id: String,
}

impl FinalSnapshotMetadata {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = value;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let canonical_snapshot = serde_jcs::to_vec(value)
                .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
            if canonical_snapshot.len() > MAX_SNAPSHOT_BYTES {
                return Err(JournalError::SnapshotTooLarge);
            }
            let (terminal, operation_id) = snapshot_terminal_expectation(value)?;
            let snapshot_digest = sha256_digest(&canonical_snapshot);
            let terminal = TerminalEventExpectation::new(
                terminal.status,
                terminal.exit_code,
                terminal.kind,
                snapshot_digest.clone(),
            );
            Ok(Self {
                snapshot_digest,
                canonical_snapshot,
                terminal,
                operation_id,
            })
        }
    }

    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    pub fn canonical_snapshot(&self) -> &[u8] {
        &self.canonical_snapshot
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn terminal_expectation(&self) -> &TerminalEventExpectation {
        &self.terminal
    }
}

#[cfg(target_os = "linux")]
fn snapshot_terminal_expectation(
    value: &serde_json::Value,
) -> Result<(TerminalEventExpectation, String), JournalError> {
    let object = value
        .as_object()
        .ok_or_else(|| JournalError::ProtocolValidation("snapshot must be an object".into()))?;
    let schema = object
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| JournalError::ProtocolValidation("snapshot schema is missing".into()))?;
    if schema != "sweepx.operation-snapshot/v1" {
        return Err(JournalError::ProtocolValidation(
            "snapshot schema is unsupported".into(),
        ));
    }
    let state = object
        .get("state")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| JournalError::ProtocolValidation("snapshot state is missing".into()))?;
    let status: sweepx_protocol::OutputStatus =
        serde_json::from_value(object.get("status").cloned().ok_or_else(|| {
            JournalError::ProtocolValidation("snapshot status is missing".into())
        })?)
        .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
    let exit_code_number = object
        .get("exitCode")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| JournalError::ProtocolValidation("snapshot exitCode is missing".into()))?;
    let exit_code: sweepx_protocol::ExitCode =
        serde_json::from_value(serde_json::json!(exit_code_number))
            .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
    if exit_code.more_conservative(sweepx_protocol::ExitCode::from(status)) != exit_code {
        return Err(JournalError::ProtocolValidation(
            "snapshot exitCode is weaker than status".into(),
        ));
    }
    let expected_state = match status {
        sweepx_protocol::OutputStatus::Ok => "completed",
        sweepx_protocol::OutputStatus::Partial => "partial",
        sweepx_protocol::OutputStatus::Unsupported => "unsupported",
        sweepx_protocol::OutputStatus::Blocked
        | sweepx_protocol::OutputStatus::AuthorizationRequired
        | sweepx_protocol::OutputStatus::Stale
        | sweepx_protocol::OutputStatus::Failed
        | sweepx_protocol::OutputStatus::NeedsReconciliation
        | sweepx_protocol::OutputStatus::Cancelled => "failed",
    };
    if state != expected_state {
        return Err(JournalError::ProtocolValidation(
            "snapshot state does not match status".into(),
        ));
    }
    let command = object
        .get("command")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| JournalError::ProtocolValidation("snapshot command is missing".into()))?;
    let kind = match command {
        "scan" => sweepx_protocol::OutputKind::ScanResult,
        "explain" => sweepx_protocol::OutputKind::ExplanationResult,
        "plan" => sweepx_protocol::OutputKind::PlanResult,
        "execute" => sweepx_protocol::OutputKind::ExecutionResult,
        "recover" => sweepx_protocol::OutputKind::RecoveryResult,
        "cancel" => sweepx_protocol::OutputKind::CancelResult,
        "status" => sweepx_protocol::OutputKind::StatusResult,
        "capabilities" => sweepx_protocol::OutputKind::CapabilitiesResult,
        "cleaner" => sweepx_protocol::OutputKind::CleanerResult,
        "audit" => sweepx_protocol::OutputKind::AuditResult,
        "cache.status" => sweepx_protocol::OutputKind::CacheStatusResult,
        _ => {
            return Err(JournalError::ProtocolValidation(
                "snapshot command is unsupported".into(),
            ));
        }
    };
    let operation_id = object
        .get("operationId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            JournalError::ProtocolValidation("snapshot operationId is missing".into())
        })?;
    if operation_id.is_empty() {
        return Err(JournalError::ProtocolValidation(
            "snapshot operationId is empty".into(),
        ));
    }
    Ok((
        TerminalEventExpectation::new(status, exit_code, kind, String::new()),
        operation_id.to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableCursor(String);

impl DurableCursor {
    pub fn parse(value: impl Into<String>) -> Result<Self, JournalError> {
        let value = value.into();
        let Some(token) = value.strip_prefix("sxcur1.") else {
            return Err(JournalError::MalformedCursor);
        };
        if value.len() > MAX_CURSOR_BYTES
            || token.len() < sweepx_protocol::MIN_DURABLE_CURSOR_TOKEN_BYTES
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(JournalError::MalformedCursor);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct EventJournal {
    #[cfg(target_os = "linux")]
    root: PathBuf,
    #[cfg(target_os = "linux")]
    anchored_root: PathBuf,
    #[cfg(target_os = "linux")]
    database_path: PathBuf,
    #[cfg(target_os = "linux")]
    root_identity: FileIdentity,
    #[cfg(target_os = "linux")]
    database_identity: FileIdentity,
    #[cfg(target_os = "linux")]
    lock_identity: FileIdentity,
    #[cfg(target_os = "linux")]
    _root_directory: File,
    #[cfg(target_os = "linux")]
    _database_file: File,
    #[cfg(target_os = "linux")]
    connection: Mutex<Connection>,
    #[cfg(target_os = "linux")]
    _lock: ExclusiveLock,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ExclusiveLock {
    file: File,
}

#[cfg(target_os = "linux")]
impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct StoredCursor {
    stream_id: String,
    operation_id: String,
    sequence: String,
    digest: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PreparedEventRecord {
    event_json: String,
    digest: String,
    previous_digest: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct VerifiedJournal {
    integrity: JournalIntegrity,
    events: Vec<EventEnvelope>,
    final_snapshot: Option<FinalSnapshotMetadata>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
type AppendState = (
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
);
#[cfg(target_os = "linux")]
type StreamMetadata = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    Option<i64>,
);

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("event journal persistence is unsupported on this platform")]
    Unsupported,
    #[error("state directory must be absolute")]
    StateDirNotAbsolute,
    #[error("event journal state does not exist")]
    StateNotFound,
    #[error("state directory {0} contains unsafe components")]
    UnsafeStateDir(String),
    #[error("state path {0} must not be a symlink")]
    SymlinkRejected(String),
    #[error("state directory {0} is not private enough")]
    StateDirNotPrivate(String),
    #[error("state file {0} is not a private regular single-link file")]
    UnsafeStateFile(String),
    #[error("concurrent writer denied")]
    ConcurrentWriterDenied,
    #[error("event journal state identity changed while open")]
    StateIdentityChanged,
    #[error("event journal connection lock is poisoned")]
    ConnectionPoisoned,
    #[error("journal quota exceeded")]
    QuotaExceeded,
    #[error("event payload exceeds durable journal limit")]
    EventTooLarge,
    #[error("decoded replay exceeds in-memory journal limit")]
    ReplayMemoryLimitExceeded,
    #[error("terminal snapshot exceeds durable journal limit")]
    SnapshotTooLarge,
    #[error("journal has reached its event limit")]
    EventLimitExceeded,
    #[error("cursor is malformed")]
    MalformedCursor,
    #[error("requested replay limit must be between 1 and 1024")]
    InvalidReplayLimit,
    #[error("event stream identity drift detected")]
    IdentityMismatch,
    #[error("the first durable event must be operation.started")]
    FirstEventNotStarted,
    #[error("the initial operation.started event must be durable")]
    StartedEventNotDurable,
    #[error("operation.started may appear only once")]
    StartedEventRepeated,
    #[error("event checkpoint history is inconsistent")]
    CheckpointMismatch,
    #[error("event time regressed")]
    TimeRegression,
    #[error("event sequence is not the next durable sequence")]
    SequenceMismatch,
    #[error("event cursor is not the next durable cursor")]
    CursorMismatch,
    #[error("event stream is already terminal")]
    AlreadyTerminal,
    #[error("complete stream append requires an empty journal")]
    JournalNotEmpty,
    #[error("terminal metadata does not match event terminal payload")]
    TerminalMetadataMismatch,
    #[error("durable stream corruption detected: {0}")]
    Corruption(&'static str),
    #[error("durable stream tampering detected")]
    TamperDetected,
    #[error("protocol validation failed: {0}")]
    ProtocolValidation(String),
    #[error("SQLite integrity check failed: {0}")]
    IntegrityCheckFailed(String),
    #[error("SQLite configuration mismatch: {0}")]
    DatabaseConfiguration(String),
    #[error(transparent)]
    Database(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl EventJournal {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, JournalError> {
        Self::open_inner(root.as_ref(), true, true)
    }

    /// Opens and verifies one replay session without first performing a redundant full-journal
    /// verification. No journal handle escapes before the session snapshot is verified.
    pub fn open_verified_replay_session(
        root: impl AsRef<Path>,
    ) -> Result<ReplaySession, JournalError> {
        let root = root.as_ref();
        #[cfg(target_os = "linux")]
        {
            ensure_existing_private_state_dir(root)?;
            for required in [LOCK_FILE, DATABASE_FILE] {
                match fs::symlink_metadata(root.join(required)) {
                    Ok(_) => ensure_private_regular_file(&root.join(required))?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Err(JournalError::StateNotFound);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Self::open_inner(root, false, false)?.snapshot_replay_session()
    }

    fn open_inner(
        root: &Path,
        verify_full_state: bool,
        create_if_missing: bool,
    ) -> Result<Self, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            let _ = verify_full_state;
            let _ = create_if_missing;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let root = root.to_path_buf();
            if create_if_missing {
                ensure_private_state_dir(&root)?;
            } else {
                ensure_existing_private_state_dir(&root)?;
            }
            let root_directory = open_state_directory(&root)?;
            ensure_local_filesystem(&root_directory)?;
            let root_identity = file_identity(&root_directory)?;
            let anchored_root =
                PathBuf::from(format!("/proc/self/fd/{}", root_directory.as_raw_fd()));
            let lock_path = anchored_root.join(LOCK_FILE);
            let lock_file = if create_if_missing {
                open_lock_file(&lock_path)?
            } else {
                open_existing_lock_file(&lock_path)?
            };
            ensure_local_filesystem(&lock_file)?;
            let lock_identity = file_identity(&lock_file)?;
            lock_file
                .try_lock_exclusive()
                .map_err(|_| JournalError::ConcurrentWriterDenied)?;
            let database_path = anchored_root.join(DATABASE_FILE);
            let database_preexisting = database_path.exists();
            if !database_preexisting && create_if_missing {
                create_private_database_file(&database_path)?;
            } else if !database_preexisting {
                return Err(JournalError::StateNotFound);
            }
            ensure_private_regular_file(&database_path)?;
            ensure_private_regular_file_if_exists(&root.join(format!("{DATABASE_FILE}-wal")))?;
            ensure_private_regular_file_if_exists(&root.join(format!("{DATABASE_FILE}-shm")))?;
            check_size_budget(&root)?;
            let database_file = open_database_file(&database_path)?;
            let database_identity = file_identity(&database_file)?;
            let sqlite_path = PathBuf::from(format!("/proc/self/fd/{}", database_file.as_raw_fd()));
            let mut connection = open_connection(&sqlite_path)?;
            if sqlite_database_identity(&connection)? != database_identity {
                return Err(JournalError::StateIdentityChanged);
            }
            if database_preexisting {
                verify_initialized_database(&connection)?;
            } else {
                initialize_database(&mut connection)?;
            }
            let journal = Self {
                root,
                anchored_root,
                database_path,
                root_identity,
                database_identity,
                lock_identity,
                _root_directory: root_directory,
                _database_file: database_file,
                connection: Mutex::new(connection),
                _lock: ExclusiveLock { file: lock_file },
            };
            if verify_full_state {
                let connection = journal.lock_connection()?;
                let _ = verify_database(&connection)?;
            }
            Ok(journal)
        }
    }

    /// Returns the exact next sequence/cursor/checkpoint tuple owned by this journal.
    /// Callers build the event with this opaque cursor and then append it; append
    /// rechecks the same state transactionally.
    pub fn next_append_position(
        &self,
        stream_id: &str,
        operation_id: &str,
        durable: bool,
    ) -> Result<JournalAppendPosition, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            let _ = stream_id;
            let _ = operation_id;
            let _ = durable;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let connection = self.lock_connection()?;
            let integrity = verify_database(&connection)?;
            if integrity.terminal_sequence.is_some() {
                return Err(JournalError::AlreadyTerminal);
            }
            let sequence = integrity
                .latest_sequence
                .checked_add(1)
                .ok_or(JournalError::EventLimitExceeded)?;
            let (stored_stream_id, stored_operation_id): (Option<String>, Option<String>) =
                connection.query_row(
                    "SELECT stream_id,operation_id FROM stream_meta WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
            match (stored_stream_id, stored_operation_id) {
                (Some(stored_stream), Some(stored_operation))
                    if stored_stream != stream_id || stored_operation != operation_id =>
                {
                    return Err(JournalError::IdentityMismatch);
                }
                (Some(_), Some(_)) => {}
                (None, None) if sequence == 1 => {}
                _ => {
                    return Err(JournalError::Corruption(
                        "stream identity metadata mismatch",
                    ));
                }
            }
            integrity.next_position(stream_id, operation_id, durable)
        }
    }

    pub fn append_event(&self, event: &EventEnvelope) -> Result<(), JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            let _ = event;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            self.append_event_inner(event, None)
        }
    }

    pub fn append_terminal_with_snapshot(
        &self,
        event: &EventEnvelope,
        final_snapshot: &FinalSnapshotMetadata,
    ) -> Result<(), JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            let _ = event;
            let _ = final_snapshot;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            validate_terminal_snapshot_pair(event, final_snapshot)?;
            self.append_event_inner(
                event,
                Some(FinalSnapshotMetadata {
                    snapshot_digest: final_snapshot.snapshot_digest.clone(),
                    canonical_snapshot: final_snapshot.canonical_snapshot.clone(),
                    terminal: final_snapshot.terminal.clone(),
                    operation_id: final_snapshot.operation_id.clone(),
                }),
            )
        }
    }

    /// Atomically appends one complete, terminal event stream to an empty journal.
    ///
    /// The journal owns durable positioning: caller-provided sequence, cursor, and checkpoint
    /// fields are ignored and replaced for every event. The replacements are copied back to the
    /// caller only after the complete stream and final snapshot commit in one `IMMEDIATE` SQLite
    /// transaction. Any error leaves both the journal and those caller fields unchanged.
    pub fn append_complete_stream(
        &self,
        events: &mut [EventEnvelope],
        final_snapshot: &FinalSnapshotMetadata,
    ) -> Result<(), JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            let _ = events;
            let _ = final_snapshot;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            ensure_complete_stream_event_count(events.len())?;
            let derived_snapshot = validated_snapshot_metadata(final_snapshot)?;

            let mut connection = self.lock_connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let integrity = verify_database(&transaction)?;
            if integrity.event_count != 0 {
                return Err(JournalError::JournalNotEmpty);
            }

            let generation_nonce = stream_generation_nonce(&transaction)?;
            let mut assigned_events = Vec::with_capacity(events.len());
            let mut records = Vec::with_capacity(events.len());
            let mut previous_digest = None::<String>;
            let mut payload_bytes = derived_snapshot.canonical_snapshot.len();
            let mut replay_decoded_bytes =
                derived_snapshot.canonical_snapshot.len().saturating_mul(4);
            let mut replay_cursor_index_bytes = 0_usize;

            for (index, source_event) in events.iter().enumerate() {
                let sequence = u64::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(JournalError::EventLimitExceeded)?;
                let mut event = source_event.clone();
                event.sequence = u128::from(sequence).into();
                event.cursor = next_durable_cursor(
                    event.stream_id.as_str(),
                    &event.operation_id.to_string(),
                    sequence,
                    &generation_nonce,
                    previous_digest.as_deref().unwrap_or("genesis"),
                );
                event.checkpoint.durable = true;
                event.checkpoint.last_durable_sequence = u128::from(sequence).into();
                event.validate_for_durable_stream().map_err(|source| {
                    JournalError::ProtocolValidation(
                        EventStreamValidationError::InvalidEvent { index, source }.to_string(),
                    )
                })?;

                let event_json = canonical_event_json(&event)?;
                if event_json.len() > MAX_EVENT_BYTES {
                    return Err(JournalError::EventTooLarge);
                }
                payload_bytes =
                    checked_complete_stream_payload_bytes(payload_bytes, event_json.len())?;
                replay_decoded_bytes = replay_decoded_bytes
                    .checked_add(estimated_event_heap_bytes(event_json.len()))
                    .ok_or(JournalError::ReplayMemoryLimitExceeded)?;
                replay_cursor_index_bytes = replay_cursor_index_bytes
                    .checked_add(estimated_cursor_index_bytes(&event.cursor))
                    .ok_or(JournalError::ReplayMemoryLimitExceeded)?;
                if replay_decoded_bytes
                    .checked_add(replay_cursor_index_bytes)
                    .is_none_or(|bytes| bytes > MAX_REPLAY_DECODED_BYTES)
                {
                    return Err(JournalError::ReplayMemoryLimitExceeded);
                }
                let digest = digest_event_record(
                    sequence,
                    previous_digest.as_deref(),
                    event_json.as_bytes(),
                );
                records.push(PreparedEventRecord {
                    event_json,
                    digest: digest.clone(),
                    previous_digest: previous_digest.clone(),
                });
                previous_digest = Some(digest);
                assigned_events.push(event);
            }

            validate_terminal_event_against_snapshot(
                assigned_events.last().ok_or_else(|| {
                    JournalError::ProtocolValidation(
                        EventStreamValidationError::EmptyStream.to_string(),
                    )
                })?,
                &derived_snapshot,
            )?;
            validate_durable_event_stream(&assigned_events, &derived_snapshot.terminal)
                .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
            ensure_append_budget(&self.anchored_root, payload_bytes)?;

            {
                let mut insert_event = transaction.prepare(
                    "INSERT INTO journal_events(sequence,stream_id,operation_id,cursor,event_json,digest,previous_digest,terminal) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                )?;
                let mut insert_cursor = transaction.prepare(
                    "INSERT INTO durable_cursors(cursor,sequence,digest,stream_id,operation_id) VALUES(?1,?2,?3,?4,?5)",
                )?;
                for (event, record) in assigned_events.iter().zip(records.iter()) {
                    let sequence = i64::try_from(u128::from(event.sequence))
                        .map_err(|_| JournalError::EventLimitExceeded)?;
                    insert_event
                        .execute(params![
                            sequence,
                            event.stream_id.as_str(),
                            event.operation_id.to_string(),
                            event.cursor.as_str(),
                            record.event_json.as_str(),
                            record.digest.as_str(),
                            record.previous_digest.as_deref(),
                            event.is_terminal_type(),
                        ])
                        .map_err(map_sqlite_quota_error)?;
                    insert_cursor
                        .execute(params![
                            event.cursor.as_str(),
                            event.sequence.to_string(),
                            record.digest.as_str(),
                            event.stream_id.as_str(),
                            event.operation_id.to_string(),
                        ])
                        .map_err(map_sqlite_quota_error)?;
                }
            }

            let first = assigned_events
                .first()
                .ok_or(JournalError::Corruption("prepared stream is empty"))?;
            let last = assigned_events
                .last()
                .ok_or(JournalError::Corruption("prepared stream is empty"))?;
            let last_record = records
                .last()
                .ok_or(JournalError::Corruption("prepared stream record is empty"))?;
            let terminal_sequence = i64::try_from(u128::from(last.sequence))
                .map_err(|_| JournalError::EventLimitExceeded)?;
            let metadata_updates = transaction.execute(
                "UPDATE stream_meta SET stream_id=?1,operation_id=?2,snapshot_digest=?3,snapshot_json=?4,terminal_sequence=?5 WHERE singleton=1 AND stream_id IS NULL AND operation_id IS NULL AND snapshot_digest IS NULL AND snapshot_json IS NULL AND terminal_sequence IS NULL",
                params![
                    first.stream_id.as_str(),
                    first.operation_id.to_string(),
                    derived_snapshot.snapshot_digest.as_str(),
                    derived_snapshot.canonical_snapshot.as_slice(),
                    terminal_sequence,
                ],
            )
            .map_err(map_sqlite_quota_error)?;
            if metadata_updates != 1 {
                return Err(JournalError::Corruption(
                    "complete stream metadata was not empty",
                ));
            }
            let head_updates = transaction.execute(
                "UPDATE journal_head SET sequence=?1,digest=?2,cursor=?3 WHERE singleton=1 AND sequence=0 AND digest IS NULL AND cursor IS NULL",
                params![
                    terminal_sequence,
                    last_record.digest.as_str(),
                    last.cursor.as_str(),
                ],
            )
            .map_err(map_sqlite_quota_error)?;
            if head_updates != 1 {
                return Err(JournalError::Corruption(
                    "complete stream journal head was not empty",
                ));
            }

            transaction.commit().map_err(map_sqlite_quota_error)?;
            for (target, assigned) in events.iter_mut().zip(assigned_events) {
                target.sequence = assigned.sequence;
                target.cursor = assigned.cursor;
                target.checkpoint = assigned.checkpoint;
            }
            Ok(())
        }
    }

    /// Opens an immutable replay snapshot after verifying the complete durable journal once.
    ///
    /// The returned session serves explicit bounded pages and never observes events appended after
    /// it was opened. This is a finite replay primitive, not a live stream or watch API.
    fn snapshot_replay_session(&self) -> Result<ReplaySession, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let connection = self.lock_connection()?;
            let transaction = connection.unchecked_transaction()?;
            let verified = verify_database_snapshot(&transaction)?;
            let mut cursor_offsets = BTreeMap::new();
            for (offset, event) in verified.events.iter().enumerate() {
                if cursor_offsets
                    .insert(event.cursor.clone(), offset + 1)
                    .is_some()
                {
                    return Err(JournalError::TamperDetected);
                }
            }
            transaction.commit()?;
            Ok(ReplaySession {
                events: verified.events,
                cursor_offsets,
                integrity: verified.integrity,
                final_snapshot: verified.final_snapshot,
            })
        }
    }

    pub fn read_all_validated(
        &self,
        expected_terminal: &TerminalEventExpectation,
    ) -> Result<Vec<EventEnvelope>, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected_terminal;
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let connection = self.lock_connection()?;
            let _ = verify_database(&connection)?;
            let mut statement =
                connection.prepare("SELECT event_json FROM journal_events ORDER BY sequence")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            let mut events = Vec::new();
            for row in rows {
                let json = row?;
                let event: EventEnvelope =
                    serde_json::from_str(&json).map_err(|_| JournalError::TamperDetected)?;
                events.push(event);
            }
            validate_durable_event_stream(&events, expected_terminal)
                .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
            Ok(events)
        }
    }

    pub fn verify_integrity(&self) -> Result<JournalIntegrity, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let connection = self.lock_connection()?;
            verify_database(&connection)
        }
    }

    pub fn read_final_snapshot(&self) -> Result<Option<FinalSnapshotMetadata>, JournalError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(JournalError::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            let connection = self.lock_connection()?;
            let integrity = verify_database(&connection)?;
            let snapshot: Option<Vec<u8>> = connection.query_row(
                "SELECT snapshot_json FROM stream_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            match (integrity.snapshot_digest, snapshot) {
                (None, None) => Ok(None),
                (Some(snapshot_digest), Some(canonical_snapshot)) => {
                    let value: serde_json::Value = serde_json::from_slice(&canonical_snapshot)
                        .map_err(|_| JournalError::TamperDetected)?;
                    let snapshot = FinalSnapshotMetadata::from_json(&value)?;
                    if snapshot.snapshot_digest != snapshot_digest {
                        return Err(JournalError::TamperDetected);
                    }
                    Ok(Some(snapshot))
                }
                _ => Err(JournalError::Corruption("snapshot metadata mismatch")),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn append_event_inner(
        &self,
        event: &EventEnvelope,
        final_snapshot: Option<FinalSnapshotMetadata>,
    ) -> Result<(), JournalError> {
        event
            .validate_for_durable_stream()
            .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
        let event_json = canonical_event_json(event)?;
        if event_json.len() > MAX_EVENT_BYTES {
            return Err(JournalError::EventTooLarge);
        }
        let append_bytes = event_json
            .len()
            .checked_add(
                final_snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.canonical_snapshot.len()),
            )
            .ok_or(JournalError::QuotaExceeded)?;
        let mut connection = self.lock_connection()?;
        ensure_append_budget(&self.anchored_root, append_bytes)?;
        let integrity = verify_database(&connection)?;
        let projected_replay_bytes = integrity
            .decoded_event_bytes
            .checked_add(integrity.cursor_index_bytes)
            .and_then(|bytes| bytes.checked_add(estimated_event_heap_bytes(event_json.len())))
            .and_then(|bytes| bytes.checked_add(estimated_cursor_index_bytes(&event.cursor)))
            .and_then(|bytes| {
                bytes.checked_add(final_snapshot.as_ref().map_or(0, |snapshot| {
                    snapshot.canonical_snapshot.len().saturating_mul(4)
                }))
            })
            .ok_or(JournalError::ReplayMemoryLimitExceeded)?;
        if projected_replay_bytes > MAX_REPLAY_DECODED_BYTES {
            return Err(JournalError::ReplayMemoryLimitExceeded);
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let (
            stream_id,
            operation_id,
            next_sequence,
            latest_cursor,
            latest_digest,
            terminal_sequence,
        ) = load_append_state(&transaction)?;
        if terminal_sequence.is_some() {
            return Err(JournalError::AlreadyTerminal);
        }
        if next_sequence > MAX_EVENTS {
            return Err(JournalError::EventLimitExceeded);
        }
        if let Some(existing_stream) = &stream_id
            && existing_stream != &event.stream_id
        {
            return Err(JournalError::IdentityMismatch);
        }
        if let Some(existing_operation) = &operation_id
            && existing_operation != &event.operation_id.to_string()
        {
            return Err(JournalError::IdentityMismatch);
        }
        if u128::from(event.sequence) != next_sequence as u128 {
            return Err(JournalError::SequenceMismatch);
        }
        if next_sequence == 1 && event.r#type != sweepx_protocol::EventType::OperationStarted {
            return Err(JournalError::FirstEventNotStarted);
        }
        if next_sequence == 1 && !event.checkpoint.durable {
            return Err(JournalError::StartedEventNotDurable);
        }
        if next_sequence > 1 && event.r#type == sweepx_protocol::EventType::OperationStarted {
            return Err(JournalError::StartedEventRepeated);
        }
        let expected_last_durable = if event.checkpoint.durable {
            u128::from(event.sequence)
        } else {
            u128::from(integrity.last_durable_sequence)
        };
        if u128::from(event.checkpoint.last_durable_sequence) != expected_last_durable {
            return Err(JournalError::CheckpointMismatch);
        }
        let emitted_at_ns = timestamp_nanoseconds(&event.emitted_at)?;
        if integrity
            .latest_emitted_at_ns
            .is_some_and(|previous| emitted_at_ns < previous)
            || integrity
                .latest_monotonic_offset_ns
                .is_some_and(|previous| u128::from(event.monotonic_offset_ns) < previous)
        {
            return Err(JournalError::TimeRegression);
        }
        if let Some(expected_cursor) = latest_cursor {
            let generation_nonce = stream_generation_nonce(&transaction)?;
            let expected_next = next_durable_cursor(
                event.stream_id.as_str(),
                &event.operation_id.to_string(),
                next_sequence as u64,
                &generation_nonce,
                latest_digest
                    .as_deref()
                    .ok_or(JournalError::Corruption("missing latest digest"))?,
            );
            if event.cursor != expected_next || event.cursor == expected_cursor {
                return Err(JournalError::CursorMismatch);
            }
        } else if next_sequence == 1 {
            let generation_nonce = stream_generation_nonce(&transaction)?;
            let initial = next_durable_cursor(
                event.stream_id.as_str(),
                &event.operation_id.to_string(),
                1,
                &generation_nonce,
                "genesis",
            );
            if event.cursor != initial {
                return Err(JournalError::CursorMismatch);
            }
        } else {
            return Err(JournalError::Corruption("missing cursor state"));
        }

        let digest = digest_event_record(
            next_sequence as u64,
            latest_digest.as_deref(),
            event_json.as_bytes(),
        );
        transaction.execute(
            "INSERT INTO journal_events(sequence,stream_id,operation_id,cursor,event_json,digest,previous_digest,terminal) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                next_sequence,
                event.stream_id.as_str(),
                event.operation_id.to_string(),
                event.cursor.as_str(),
                event_json,
                digest,
                latest_digest,
                event.is_terminal_type(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO durable_cursors(cursor,sequence,digest,stream_id,operation_id) VALUES(?1,?2,?3,?4,?5)",
            params![
                event.cursor.as_str(),
                event.sequence.to_string(),
                digest,
                event.stream_id.as_str(),
                event.operation_id.to_string(),
            ],
        )?;
        let terminal_sequence_value = if event.is_terminal_type() {
            Some(next_sequence)
        } else {
            None
        };
        if let Some(snapshot) = &final_snapshot {
            transaction.execute(
                "UPDATE stream_meta SET snapshot_digest=?1,snapshot_json=?2,terminal_sequence=?3 WHERE singleton=1",
                params![
                    snapshot.snapshot_digest,
                    snapshot.canonical_snapshot,
                    terminal_sequence_value
                ],
            )?;
        } else if event.is_terminal_type() {
            return Err(JournalError::TerminalMetadataMismatch);
        }
        transaction.execute(
            "UPDATE journal_head SET sequence=?1,digest=?2,cursor=?3 WHERE singleton=1 AND sequence=?4",
            params![next_sequence, digest, event.cursor.as_str(), next_sequence - 1],
        )?;
        if stream_id.is_none() {
            transaction.execute(
                "UPDATE stream_meta SET stream_id=?1,operation_id=?2 WHERE singleton=1",
                params![event.stream_id.as_str(), event.operation_id.to_string()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn lock_connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, JournalError> {
        ensure_private_state_dir(&self.root)?;
        let anchored_root = self.anchored_root.as_path();
        check_size_budget(anchored_root)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| JournalError::ConnectionPoisoned)?;
        if file_identity_for_directory_path(&self.root)? != self.root_identity
            || file_identity_for_path(&self.database_path)? != self.database_identity
            || file_identity_for_path(&anchored_root.join(LOCK_FILE))? != self.lock_identity
            || sqlite_database_identity(&connection)? != self.database_identity
        {
            return Err(JournalError::StateIdentityChanged);
        }
        ensure_private_regular_file(&self.database_path)?;
        ensure_private_regular_file_if_exists(&anchored_root.join(format!("{DATABASE_FILE}-wal")))?;
        ensure_private_regular_file_if_exists(&anchored_root.join(format!("{DATABASE_FILE}-shm")))?;
        ensure_private_regular_file_if_exists(&anchored_root.join(format!("{DATABASE_FILE}-wal")))?;
        ensure_private_regular_file_if_exists(&anchored_root.join(format!("{DATABASE_FILE}-shm")))?;
        Ok(connection)
    }
}

#[cfg(target_os = "linux")]
fn load_append_state(transaction: &Transaction<'_>) -> Result<AppendState, JournalError> {
    let head: (i64, Option<String>, Option<String>) = transaction.query_row(
        "SELECT sequence,digest,cursor FROM journal_head WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let stream_meta: (Option<String>, Option<String>, Option<i64>) = transaction.query_row(
        "SELECT stream_id,operation_id,terminal_sequence FROM stream_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok((
        stream_meta.0,
        stream_meta.1,
        head.0
            .checked_add(1)
            .ok_or(JournalError::Corruption("sequence overflow"))?,
        head.2,
        head.1,
        stream_meta.2,
    ))
}

#[cfg(target_os = "linux")]
fn stream_generation_nonce(connection: &Connection) -> Result<String, JournalError> {
    let nonce: String = connection.query_row(
        "SELECT generation_nonce FROM stream_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if nonce.len() != 43
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(JournalError::Corruption("invalid journal generation nonce"));
    }
    Ok(nonce)
}

#[cfg(target_os = "linux")]
fn verify_database(connection: &Connection) -> Result<JournalIntegrity, JournalError> {
    Ok(verify_database_snapshot(connection)?.integrity)
}

#[cfg(target_os = "linux")]
fn verify_database_snapshot(connection: &Connection) -> Result<VerifiedJournal, JournalError> {
    verify_connection_pragmas(connection)?;
    verify_initialized_database(connection)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(JournalError::IntegrityCheckFailed(integrity));
    }

    let mut statement = connection.prepare(
        "SELECT sequence,stream_id,operation_id,cursor,event_json,digest,previous_digest,terminal FROM journal_events ORDER BY sequence",
    )?;
    let mut rows = statement.query([])?;
    let mut events = Vec::new();
    let mut decoded_event_bytes = 0_usize;
    let mut cursor_index_bytes = 0_usize;
    let mut cursor_rows = Vec::new();
    let mut previous_digest = None::<String>;
    let mut latest_cursor = None::<String>;
    let mut latest_sequence = 0_u64;
    let mut terminal_sequence = None::<u64>;
    let generation_nonce = stream_generation_nonce(connection)?;
    let mut last_durable_sequence = 0_u64;
    let mut latest_emitted_at_ns = None::<i128>;
    let mut latest_monotonic_offset_ns = None::<u128>;
    while let Some(row) = rows.next()? {
        if latest_sequence >= MAX_EVENTS as u64 {
            return Err(JournalError::EventLimitExceeded);
        }
        let sequence: i64 = row.get(0)?;
        let stored_stream: String = row.get(1)?;
        let stored_operation: String = row.get(2)?;
        let stored_cursor: String = row.get(3)?;
        let event_json: String = row.get(4)?;
        if event_json.len() > MAX_EVENT_BYTES {
            return Err(JournalError::EventTooLarge);
        }
        let estimated_event_bytes = estimated_event_heap_bytes(event_json.len());
        decoded_event_bytes = decoded_event_bytes
            .checked_add(estimated_event_bytes)
            .ok_or(JournalError::ReplayMemoryLimitExceeded)?;
        cursor_index_bytes = cursor_index_bytes
            .checked_add(estimated_cursor_index_bytes(&stored_cursor))
            .ok_or(JournalError::ReplayMemoryLimitExceeded)?;
        if decoded_event_bytes
            .checked_add(cursor_index_bytes)
            .is_none_or(|bytes| bytes > MAX_REPLAY_DECODED_BYTES)
        {
            return Err(JournalError::ReplayMemoryLimitExceeded);
        }
        let stored_digest: String = row.get(5)?;
        let stored_previous: Option<String> = row.get(6)?;
        let stored_terminal: bool = row.get(7)?;
        let sequence_u64 = u64::try_from(sequence).map_err(|_| JournalError::TamperDetected)?;
        if sequence_u64 != latest_sequence + 1 {
            return Err(JournalError::Corruption("sequence gap"));
        }
        if stored_previous != previous_digest {
            return Err(JournalError::TamperDetected);
        }
        let event: EventEnvelope =
            serde_json::from_str(&event_json).map_err(|_| JournalError::TamperDetected)?;
        event
            .validate_for_durable_stream()
            .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
        if event.sequence != u128::from(sequence_u64).into() {
            return Err(JournalError::TamperDetected);
        }
        if sequence_u64 == 1 && event.r#type != sweepx_protocol::EventType::OperationStarted {
            return Err(JournalError::FirstEventNotStarted);
        }
        if sequence_u64 > 1 && event.r#type == sweepx_protocol::EventType::OperationStarted {
            return Err(JournalError::StartedEventRepeated);
        }
        if stored_stream != event.stream_id || stored_operation != event.operation_id.to_string() {
            return Err(JournalError::TamperDetected);
        }
        if stored_cursor != event.cursor || stored_terminal != event.is_terminal_type() {
            return Err(JournalError::TamperDetected);
        }
        let expected_cursor = if sequence_u64 == 1 {
            next_durable_cursor(
                &event.stream_id,
                &event.operation_id.to_string(),
                1,
                &generation_nonce,
                "genesis",
            )
        } else {
            next_durable_cursor(
                &event.stream_id,
                &event.operation_id.to_string(),
                sequence_u64,
                &generation_nonce,
                previous_digest
                    .as_deref()
                    .ok_or(JournalError::Corruption("missing previous digest"))?,
            )
        };
        if stored_cursor != expected_cursor {
            return Err(JournalError::TamperDetected);
        }
        let emitted_at_ns = timestamp_nanoseconds(&event.emitted_at)?;
        if latest_emitted_at_ns.is_some_and(|previous| emitted_at_ns < previous)
            || latest_monotonic_offset_ns
                .is_some_and(|previous| u128::from(event.monotonic_offset_ns) < previous)
        {
            return Err(JournalError::TimeRegression);
        }
        latest_emitted_at_ns = Some(emitted_at_ns);
        latest_monotonic_offset_ns = Some(event.monotonic_offset_ns.into());
        let expected_checkpoint = if event.checkpoint.durable {
            sequence_u64
        } else {
            last_durable_sequence
        };
        if u128::from(event.checkpoint.last_durable_sequence) != u128::from(expected_checkpoint) {
            return Err(JournalError::CheckpointMismatch);
        }
        if event.checkpoint.durable {
            last_durable_sequence = sequence_u64;
        }
        let expected_digest = digest_event_record(
            sequence_u64,
            previous_digest.as_deref(),
            event_json.as_bytes(),
        );
        if stored_digest != expected_digest {
            return Err(JournalError::TamperDetected);
        }
        if event.is_terminal_type() {
            if terminal_sequence.is_some() {
                return Err(JournalError::Corruption("duplicate terminal"));
            }
            terminal_sequence = Some(sequence_u64);
        }
        latest_sequence = sequence_u64;
        latest_cursor = Some(stored_cursor);
        previous_digest = Some(stored_digest);
        cursor_rows.push((
            event.cursor.clone(),
            StoredCursor {
                stream_id: event.stream_id.clone(),
                operation_id: event.operation_id.to_string(),
                sequence: sequence_u64.to_string(),
                digest: previous_digest
                    .clone()
                    .ok_or(JournalError::Corruption("missing stored digest"))?,
            },
        ));
        events.push(event);
    }

    let head: (i64, Option<String>, Option<String>) = connection.query_row(
        "SELECT sequence,digest,cursor FROM journal_head WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if head.0 != latest_sequence as i64 || head.1 != previous_digest || head.2 != latest_cursor {
        return Err(JournalError::Corruption("journal head mismatch"));
    }
    let meta: StreamMetadata = connection.query_row(
        "SELECT stream_id,operation_id,snapshot_digest,snapshot_json,terminal_sequence FROM stream_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    if events.is_empty() {
        if meta.0.is_some()
            || meta.1.is_some()
            || meta.2.is_some()
            || meta.3.is_some()
            || meta.4.is_some()
        {
            return Err(JournalError::Corruption("empty journal metadata mismatch"));
        }
    } else {
        let first_operation_id = events[0].operation_id.to_string();
        if meta.0.as_deref() != Some(events[0].stream_id.as_str())
            || meta.1.as_deref() != Some(first_operation_id.as_str())
        {
            return Err(JournalError::Corruption(
                "stream identity metadata mismatch",
            ));
        }
    }
    if meta.4.map(|value| value as u64) != terminal_sequence {
        return Err(JournalError::Corruption("terminal metadata mismatch"));
    }
    if terminal_sequence.is_some() != meta.2.is_some()
        || terminal_sequence.is_some() != meta.3.is_some()
    {
        return Err(JournalError::Corruption("snapshot metadata mismatch"));
    }
    let final_snapshot = if let (Some(snapshot_digest), Some(snapshot_json)) = (&meta.2, &meta.3) {
        if snapshot_json.len() > MAX_SNAPSHOT_BYTES
            || sha256_digest(snapshot_json) != *snapshot_digest
        {
            return Err(JournalError::TamperDetected);
        }
        let projected_replay_bytes = decoded_event_bytes
            .checked_add(cursor_index_bytes)
            .and_then(|bytes| bytes.checked_add(snapshot_json.len().saturating_mul(4)))
            .ok_or(JournalError::ReplayMemoryLimitExceeded)?;
        if projected_replay_bytes > MAX_REPLAY_DECODED_BYTES {
            return Err(JournalError::ReplayMemoryLimitExceeded);
        }
        let value: serde_json::Value =
            serde_json::from_slice(snapshot_json).map_err(|_| JournalError::TamperDetected)?;
        let snapshot =
            FinalSnapshotMetadata::from_json(&value).map_err(|_| JournalError::TamperDetected)?;
        if snapshot.snapshot_digest != *snapshot_digest {
            return Err(JournalError::TamperDetected);
        }
        Some(snapshot)
    } else {
        None
    };
    verify_cursor_table(connection, &cursor_rows)?;
    if !events.is_empty() {
        if let Some(snapshot) = &final_snapshot {
            if meta.1.as_deref() != Some(snapshot.operation_id()) {
                return Err(JournalError::TamperDetected);
            }
            validate_durable_event_stream(&events, snapshot.terminal_expectation())
                .map_err(map_stream_validation_error)?;
        } else if events.iter().any(EventEnvelope::is_terminal_type) {
            return Err(JournalError::Corruption(
                "terminal stream missing snapshot metadata",
            ));
        }
    }

    Ok(VerifiedJournal {
        integrity: JournalIntegrity {
            event_count: latest_sequence,
            terminal_sequence,
            latest_sequence,
            latest_cursor,
            last_durable_sequence,
            snapshot_digest: meta.2,
            decoded_event_bytes,
            cursor_index_bytes,
            latest_record_digest: previous_digest,
            latest_emitted_at_ns,
            latest_monotonic_offset_ns,
            generation_nonce,
        },
        events,
        final_snapshot,
    })
}

#[cfg(target_os = "linux")]
fn timestamp_nanoseconds(value: &str) -> Result<i128, JournalError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|timestamp| timestamp.unix_timestamp_nanos())
        .map_err(|error| JournalError::ProtocolValidation(error.to_string()))
}

#[cfg(target_os = "linux")]
fn ensure_complete_stream_event_count(event_count: usize) -> Result<(), JournalError> {
    if event_count > MAX_EVENTS as usize {
        return Err(JournalError::EventLimitExceeded);
    }
    if event_count == 0 {
        return Err(JournalError::ProtocolValidation(
            EventStreamValidationError::EmptyStream.to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn checked_complete_stream_payload_bytes(
    accumulated: usize,
    event_bytes: usize,
) -> Result<usize, JournalError> {
    let total = accumulated
        .checked_add(event_bytes)
        .and_then(|value| value.checked_add(MAX_BATCH_STORAGE_OVERHEAD_PER_EVENT))
        .ok_or(JournalError::QuotaExceeded)?;
    let reserve =
        usize::try_from(MAX_APPEND_RESERVE_BYTES).map_err(|_| JournalError::QuotaExceeded)?;
    let maximum_payload = usize::try_from(MAX_DATABASE_BYTES)
        .map_err(|_| JournalError::QuotaExceeded)?
        .checked_sub(reserve)
        .ok_or(JournalError::QuotaExceeded)?;
    if total > maximum_payload {
        return Err(JournalError::QuotaExceeded);
    }
    Ok(total)
}

#[cfg(target_os = "linux")]
fn map_sqlite_quota_error(error: rusqlite::Error) -> JournalError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) {
        JournalError::QuotaExceeded
    } else {
        JournalError::Database(error)
    }
}

#[cfg(target_os = "linux")]
fn validated_snapshot_metadata(
    final_snapshot: &FinalSnapshotMetadata,
) -> Result<FinalSnapshotMetadata, JournalError> {
    let value = serde_json::from_slice::<serde_json::Value>(&final_snapshot.canonical_snapshot)
        .map_err(|_| JournalError::TerminalMetadataMismatch)?;
    let derived = FinalSnapshotMetadata::from_json(&value)?;
    if derived != *final_snapshot {
        return Err(JournalError::TerminalMetadataMismatch);
    }
    Ok(derived)
}

#[cfg(target_os = "linux")]
fn validate_terminal_event_against_snapshot(
    event: &EventEnvelope,
    final_snapshot: &FinalSnapshotMetadata,
) -> Result<(), JournalError> {
    let terminal = event
        .terminal_payload()
        .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
    if terminal.snapshot_digest != final_snapshot.snapshot_digest
        || terminal.snapshot_digest != final_snapshot.terminal.snapshot_digest
        || terminal.status != final_snapshot.terminal.status
        || terminal.exit_code != final_snapshot.terminal.exit_code
        || terminal.kind != final_snapshot.terminal.kind
        || event.operation_id.to_string() != final_snapshot.operation_id
    {
        return Err(JournalError::TerminalMetadataMismatch);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_terminal_snapshot_pair(
    event: &EventEnvelope,
    final_snapshot: &FinalSnapshotMetadata,
) -> Result<(), JournalError> {
    let derived_snapshot = validated_snapshot_metadata(final_snapshot)?;
    validate_terminal_event_against_snapshot(event, &derived_snapshot)
}

#[cfg(target_os = "linux")]
fn map_stream_validation_error(error: EventStreamValidationError) -> JournalError {
    match error {
        EventStreamValidationError::SequenceMismatch { .. }
        | EventStreamValidationError::DuplicateCursor { .. }
        | EventStreamValidationError::CheckpointHistoryMismatch { .. }
        | EventStreamValidationError::TerminalNotLast
        | EventStreamValidationError::TerminalCount { .. }
        | EventStreamValidationError::FirstEventNotStarted
        | EventStreamValidationError::StartedEventNotDurable
        | EventStreamValidationError::StartedEventRepeated { .. }
        | EventStreamValidationError::StreamIdMismatch { .. }
        | EventStreamValidationError::OperationIdMismatch { .. } => JournalError::TamperDetected,
        other => JournalError::ProtocolValidation(other.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn next_durable_cursor(
    stream_id: &str,
    operation_id: &str,
    sequence: u64,
    generation_nonce: &str,
    basis: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(stream_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(operation_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(sequence.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(generation_nonce.as_bytes());
    hasher.update(b"\n");
    hasher.update(basis.as_bytes());
    format!("sxcur1.{}", base64url(&hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn digest_event_record(sequence: u64, previous_digest: Option<&str>, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(sequence.to_string().as_bytes());
    hasher.update(b"\n");
    if let Some(previous) = previous_digest {
        hasher.update(previous.as_bytes());
    }
    hasher.update(b"\n");
    hasher.update(payload);
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn random_generation_nonce() -> Result<String, JournalError> {
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes).map_err(|_| {
        JournalError::DatabaseConfiguration("secure journal generation failed".to_string())
    })?;
    Ok(base64url(&bytes))
}

#[cfg(target_os = "linux")]
fn canonical_event_json(event: &EventEnvelope) -> Result<String, JournalError> {
    let value = serde_json::to_value(event)
        .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
    let string = serde_jcs::to_string(&value)
        .map_err(|error| JournalError::ProtocolValidation(error.to_string()))?;
    Ok(string)
}

#[cfg(target_os = "linux")]
fn estimated_event_heap_bytes(encoded_bytes: usize) -> usize {
    // serde_json::Value may use several allocations per node. A four-times encoded-size
    // allowance plus the envelope itself is a conservative admission estimate; it is not an
    // allocator-exact RSS measurement.
    encoded_bytes
        .saturating_mul(4)
        .saturating_add(std::mem::size_of::<EventEnvelope>())
}

#[cfg(target_os = "linux")]
fn estimated_cursor_index_bytes(cursor: &str) -> usize {
    // Charge both the owned key and conservative B-tree node/allocator overhead.
    cursor
        .len()
        .saturating_add(std::mem::size_of::<(String, usize)>())
        .saturating_add(128)
}

#[cfg(target_os = "linux")]
fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let block = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | bytes[index + 2] as u32;
        out.push(TABLE[((block >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((block >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((block >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(block & 0x3f) as usize] as char);
        index += 3;
    }
    match bytes.len() - index {
        1 => {
            let block = (bytes[index] as u32) << 16;
            out.push(TABLE[((block >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((block >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let block = ((bytes[index] as u32) << 16) | ((bytes[index + 1] as u32) << 8);
            out.push(TABLE[((block >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((block >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((block >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

#[cfg(target_os = "linux")]
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

#[cfg(target_os = "linux")]
fn verify_cursor_table(
    connection: &Connection,
    expected: &[(String, StoredCursor)],
) -> Result<(), JournalError> {
    let mut statement = connection.prepare(
        "SELECT cursor,sequence,digest,stream_id,operation_id FROM durable_cursors ORDER BY CAST(sequence AS INTEGER), cursor",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            StoredCursor {
                sequence: row.get(1)?,
                digest: row.get(2)?,
                stream_id: row.get(3)?,
                operation_id: row.get(4)?,
            },
        ))
    })?;
    let actual = rows.collect::<Result<Vec<_>, _>>()?;
    if actual.len() != expected.len() {
        return Err(JournalError::Corruption(
            "durable cursor table cardinality mismatch",
        ));
    }
    for (actual_row, expected_row) in actual.iter().zip(expected.iter()) {
        if actual_row != expected_row {
            return Err(JournalError::TamperDetected);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_size_budget(root: &Path) -> Result<(), JournalError> {
    let db = file_len_if_exists(&root.join(DATABASE_FILE))?;
    let wal = file_len_if_exists(&root.join(format!("{DATABASE_FILE}-wal")))?;
    let shm = file_len_if_exists(&root.join(format!("{DATABASE_FILE}-shm")))?;
    let total = db
        .checked_add(wal)
        .and_then(|value| value.checked_add(shm))
        .ok_or(JournalError::QuotaExceeded)?;
    if db > MAX_DATABASE_BYTES || wal > MAX_WAL_BYTES || total > MAX_TOTAL_BYTES {
        return Err(JournalError::QuotaExceeded);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_append_budget(root: &Path, event_bytes: usize) -> Result<(), JournalError> {
    let current = current_size_bytes(root)?;
    let reserve = u64::try_from(event_bytes)
        .map_err(|_| JournalError::QuotaExceeded)?
        .checked_add(MAX_APPEND_RESERVE_BYTES)
        .ok_or(JournalError::QuotaExceeded)?;
    if current
        .checked_add(reserve)
        .is_none_or(|projected| projected > MAX_TOTAL_BYTES)
    {
        return Err(JournalError::QuotaExceeded);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn current_size_bytes(root: &Path) -> Result<u64, JournalError> {
    [
        root.join(DATABASE_FILE),
        root.join(format!("{DATABASE_FILE}-wal")),
        root.join(format!("{DATABASE_FILE}-shm")),
    ]
    .into_iter()
    .try_fold(0_u64, |total, path| {
        total
            .checked_add(file_len_if_exists(&path)?)
            .ok_or(JournalError::QuotaExceeded)
    })
}

#[cfg(target_os = "linux")]
fn file_len_if_exists(path: &Path) -> Result<u64, JournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(JournalError::SymlinkRejected(path.display().to_string()));
            }
            Ok(metadata.len())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn ensure_private_state_dir(root: &Path) -> Result<(), JournalError> {
    if !root.is_absolute() {
        return Err(JournalError::StateDirNotAbsolute);
    }
    for component in root.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Normal(_) => {}
            _ => return Err(JournalError::UnsafeStateDir(root.display().to_string())),
        }
    }
    let mut current = PathBuf::from("/");
    for component in root.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(part) => current.push(part),
            _ => return Err(JournalError::UnsafeStateDir(root.display().to_string())),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(JournalError::SymlinkRejected(current.display().to_string()));
                }
                if !metadata.is_dir() {
                    return Err(JournalError::UnsafeStateDir(current.display().to_string()));
                }
                if current == root {
                    validate_private_directory(&current, &metadata)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&current)?;
                let metadata = fs::symlink_metadata(&current)?;
                validate_private_directory(&current, &metadata)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_existing_private_state_dir(root: &Path) -> Result<(), JournalError> {
    if !root.is_absolute() {
        return Err(JournalError::StateDirNotAbsolute);
    }
    let mut current = PathBuf::from("/");
    for component in root.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(part) => current.push(part),
            _ => return Err(JournalError::UnsafeStateDir(root.display().to_string())),
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(JournalError::StateNotFound);
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(JournalError::SymlinkRejected(current.display().to_string()));
        }
        if !metadata.is_dir() {
            return Err(JournalError::UnsafeStateDir(current.display().to_string()));
        }
        if current == root {
            validate_private_directory(&current, &metadata)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), JournalError> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(JournalError::StateDirNotPrivate(path.display().to_string()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_state_directory(path: &Path) -> Result<File, JournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_private_directory(path, &directory.metadata()?)?;
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn file_identity(file: &File) -> Result<FileIdentity, JournalError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn file_identity_for_path(path: &Path) -> Result<FileIdentity, JournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file_identity(&file)
}

#[cfg(target_os = "linux")]
fn open_database_file(path: &Path) -> Result<File, JournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(JournalError::UnsafeStateFile(path.display().to_string()));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn file_identity_for_directory_path(path: &Path) -> Result<FileIdentity, JournalError> {
    file_identity(&open_state_directory(path)?)
}

#[cfg(target_os = "linux")]
fn sqlite_database_identity(connection: &Connection) -> Result<FileIdentity, JournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    let filename: String = connection.query_row(
        "SELECT file FROM pragma_database_list WHERE name='main'",
        [],
        |row| row.get(0),
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(filename)?;
    file_identity(&file)
}

#[cfg(target_os = "linux")]
fn ensure_private_regular_file(path: &Path) -> Result<(), JournalError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(JournalError::SymlinkRejected(path.display().to_string()));
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let metadata = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(JournalError::UnsafeStateFile(path.display().to_string()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_private_regular_file_if_exists(path: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_private_regular_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn open_lock_file(path: &Path) -> Result<File, JournalError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(JournalError::SymlinkRejected(path.display().to_string()));
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure_private_regular_file(path)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_existing_lock_file(path: &Path) -> Result<File, JournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(JournalError::SymlinkRejected(path.display().to_string()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(JournalError::StateNotFound);
        }
        Err(error) => return Err(error.into()),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure_private_regular_file(path)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn create_private_database_file(path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?
        .sync_all()?;
    sync_directory(
        path.parent()
            .ok_or_else(|| JournalError::UnsafeStateDir(path.display().to_string()))?,
    )
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> Result<(), JournalError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_local_filesystem(file: &File) -> Result<(), JournalError> {
    use std::os::fd::AsRawFd;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let filesystem_type = unsafe { stat.assume_init() }.f_type as u32;
    const KNOWN_LOCAL: &[u32] = &[0x0000_ef53, 0x5846_5342, 0x9123_683e, 0xf2f5_2010];
    if KNOWN_LOCAL.contains(&filesystem_type) {
        Ok(())
    } else {
        Err(JournalError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
fn open_connection(path: &Path) -> Result<Connection, JournalError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DDL, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DQS_DML, false)?;
    connection.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA mmap_size=0; PRAGMA trusted_schema=OFF; PRAGMA read_uncommitted=OFF; PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA wal_autocheckpoint=64; PRAGMA journal_size_limit=8388608;",
    )?;
    connection.pragma_update(None, "max_page_count", MAX_PAGE_COUNT)?;
    connection.pragma_update(None, "journal_size_limit", MAX_WAL_BYTES as i64)?;
    let journal: String =
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(JournalError::DatabaseConfiguration(
            "journal_mode is not WAL".to_string(),
        ));
    }
    verify_connection_pragmas(&connection)?;
    Ok(connection)
}

#[cfg(target_os = "linux")]
fn verify_connection_pragmas(connection: &Connection) -> Result<(), JournalError> {
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let mmap_size: i64 = connection.pragma_query_value(None, "mmap_size", |row| row.get(0))?;
    let trusted: i64 = connection.pragma_query_value(None, "trusted_schema", |row| row.get(0))?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let max_page_count: i64 =
        connection.pragma_query_value(None, "max_page_count", |row| row.get(0))?;
    let journal_size_limit: i64 =
        connection.pragma_query_value(None, "journal_size_limit", |row| row.get(0))?;
    let wal_autocheckpoint: i64 =
        connection.pragma_query_value(None, "wal_autocheckpoint", |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.pragma_query_value(None, "read_uncommitted", |row| row.get(0))?;
    let locking_mode: String =
        connection.pragma_query_value(None, "locking_mode", |row| row.get(0))?;
    let temp_store: i64 = connection.pragma_query_value(None, "temp_store", |row| row.get(0))?;
    if foreign_keys != 1
        || synchronous != 2
        || mmap_size != 0
        || trusted != 0
        || !journal.eq_ignore_ascii_case("wal")
        || page_size != PAGE_SIZE
        || max_page_count != MAX_PAGE_COUNT
        || journal_size_limit != MAX_WAL_BYTES as i64
        || wal_autocheckpoint != 64
        || read_uncommitted != 0
        || !locking_mode.eq_ignore_ascii_case("exclusive")
        || temp_store != 2
        || !connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?
        || connection.db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)?
    {
        return Err(JournalError::DatabaseConfiguration(format!(
            "required SQLite safety settings are not active: foreign_keys={foreign_keys}, synchronous={synchronous}, mmap_size={mmap_size}, trusted_schema={trusted}, journal_mode={journal}, page_size={page_size}, max_page_count={max_page_count}, journal_size_limit={journal_size_limit}, wal_autocheckpoint={wal_autocheckpoint}, read_uncommitted={read_uncommitted}, locking_mode={locking_mode}, temp_store={temp_store}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_initialized_database(connection: &Connection) -> Result<(), JournalError> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 =
        connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != APPLICATION_ID || user_version != USER_VERSION {
        return Err(JournalError::DatabaseConfiguration(
            "unexpected SQLite application_id or user_version".to_string(),
        ));
    }
    let schema: String = connection.query_row(
        "SELECT schema_version FROM stream_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if schema != SCHEMA_VERSION {
        return Err(JournalError::DatabaseConfiguration(
            "schema version mismatch".to_string(),
        ));
    }
    verify_schema_objects(connection)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_schema_objects(connection: &Connection) -> Result<(), JournalError> {
    let expected = BTreeMap::from([
        (
            "durable_cursors".to_string(),
            normalize_sql(DURABLE_CURSORS_SQL),
        ),
        (
            "journal_events".to_string(),
            normalize_sql(JOURNAL_EVENTS_SQL),
        ),
        (
            "journal_events_no_delete".to_string(),
            normalize_sql(EVENTS_NO_DELETE_SQL),
        ),
        (
            "journal_events_no_update".to_string(),
            normalize_sql(EVENTS_NO_UPDATE_SQL),
        ),
        ("journal_head".to_string(), normalize_sql(JOURNAL_HEAD_SQL)),
        ("stream_meta".to_string(), normalize_sql(STREAM_META_SQL)),
    ]);
    let mut statement = connection.prepare(
        "SELECT name,sql FROM sqlite_schema WHERE type IN ('table','trigger') AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let actual = rows
        .collect::<Result<BTreeMap<_, _>, _>>()?
        .into_iter()
        .map(|(name, sql)| (name, normalize_sql(&sql)))
        .collect::<BTreeMap<_, _>>();
    if actual != expected {
        return Err(JournalError::DatabaseConfiguration(
            "journal schema or append-only triggers changed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn normalize_sql(sql: &str) -> String {
    sql.bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b';')
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

#[cfg(target_os = "linux")]
fn initialize_database(connection: &mut Connection) -> Result<(), JournalError> {
    connection.pragma_update(None, "page_size", PAGE_SIZE)?;
    connection.pragma_update(None, "max_page_count", MAX_PAGE_COUNT)?;
    connection.pragma_update(None, "application_id", APPLICATION_ID)?;
    connection.pragma_update(None, "user_version", USER_VERSION)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_SQL)?;
    transaction.execute(
        "INSERT INTO stream_meta(singleton,schema_version,generation_nonce,stream_id,operation_id,snapshot_digest,snapshot_json,terminal_sequence) VALUES(1,?1,?2,NULL,NULL,NULL,NULL,NULL)",
        params![SCHEMA_VERSION, random_generation_nonce()?],
    )?;
    transaction.execute(
        "INSERT INTO journal_head(singleton,sequence,digest,cursor) VALUES(1,0,NULL,NULL)",
        [],
    )?;
    transaction.commit()?;
    connection.pragma_update(None, "max_page_count", MAX_PAGE_COUNT)?;
    sync_directory(
        connection
            .path()
            .and_then(|path| Path::new(path).parent())
            .ok_or_else(|| {
                JournalError::DatabaseConfiguration("database path unavailable".to_string())
            })?,
    )?;
    verify_initialized_database(connection)?;
    Ok(())
}

#[cfg(target_os = "linux")]
const STREAM_META_SQL: &str = r#"CREATE TABLE stream_meta(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version TEXT NOT NULL,
  generation_nonce TEXT NOT NULL,
  stream_id TEXT,
  operation_id TEXT,
  snapshot_digest TEXT,
  snapshot_json BLOB,
  terminal_sequence INTEGER
) STRICT"#;
#[cfg(target_os = "linux")]
const JOURNAL_HEAD_SQL: &str = r#"CREATE TABLE journal_head(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  sequence INTEGER NOT NULL CHECK(sequence>=0),
  digest TEXT,
  cursor TEXT
) STRICT"#;
#[cfg(target_os = "linux")]
const JOURNAL_EVENTS_SQL: &str = r#"CREATE TABLE journal_events(
  sequence INTEGER PRIMARY KEY CHECK(sequence>0),
  stream_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  cursor TEXT NOT NULL UNIQUE,
  event_json TEXT NOT NULL,
  digest TEXT NOT NULL,
  previous_digest TEXT,
  terminal INTEGER NOT NULL CHECK(terminal IN (0,1))
) STRICT"#;
#[cfg(target_os = "linux")]
const DURABLE_CURSORS_SQL: &str = r#"CREATE TABLE durable_cursors(
  cursor TEXT PRIMARY KEY,
  sequence TEXT NOT NULL,
  digest TEXT NOT NULL,
  stream_id TEXT NOT NULL,
  operation_id TEXT NOT NULL
) STRICT"#;
#[cfg(target_os = "linux")]
const EVENTS_NO_UPDATE_SQL: &str = "CREATE TRIGGER journal_events_no_update BEFORE UPDATE ON journal_events BEGIN SELECT RAISE(ABORT,'events are append-only'); END";
#[cfg(target_os = "linux")]
const EVENTS_NO_DELETE_SQL: &str = "CREATE TRIGGER journal_events_no_delete BEFORE DELETE ON journal_events BEGIN SELECT RAISE(ABORT,'events are append-only'); END";
#[cfg(target_os = "linux")]
const SCHEMA_SQL: &str = "
CREATE TABLE stream_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version TEXT NOT NULL,generation_nonce TEXT NOT NULL,stream_id TEXT,operation_id TEXT,snapshot_digest TEXT,snapshot_json BLOB,terminal_sequence INTEGER) STRICT;
CREATE TABLE journal_head(singleton INTEGER PRIMARY KEY CHECK(singleton=1),sequence INTEGER NOT NULL CHECK(sequence>=0),digest TEXT,cursor TEXT) STRICT;
CREATE TABLE journal_events(sequence INTEGER PRIMARY KEY CHECK(sequence>0),stream_id TEXT NOT NULL,operation_id TEXT NOT NULL,cursor TEXT NOT NULL UNIQUE,event_json TEXT NOT NULL,digest TEXT NOT NULL,previous_digest TEXT,terminal INTEGER NOT NULL CHECK(terminal IN (0,1))) STRICT;
CREATE TABLE durable_cursors(cursor TEXT PRIMARY KEY,sequence TEXT NOT NULL,digest TEXT NOT NULL,stream_id TEXT NOT NULL,operation_id TEXT NOT NULL) STRICT;
CREATE TRIGGER journal_events_no_update BEFORE UPDATE ON journal_events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
CREATE TRIGGER journal_events_no_delete BEFORE DELETE ON journal_events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
";

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use serde_json::Value;
    #[cfg(target_os = "linux")]
    use sweepx_model::{DecimalU128, OperationId};
    #[cfg(target_os = "linux")]
    use sweepx_protocol::{
        EventCheckpoint, EventEnvelope, EventPhase, EventType, ExitCode, OutputKind, OutputStatus,
        TerminalEventPayload,
    };
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    fn private_root(temp: &TempDir) -> PathBuf {
        let root = temp.path().join("journal");
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        root
    }

    #[cfg(target_os = "linux")]
    fn event(
        sequence: u128,
        cursor: String,
        durable: bool,
        event_type: EventType,
        terminal: bool,
        payload: Value,
    ) -> EventEnvelope {
        EventEnvelope {
            schema: sweepx_protocol::EVENT_SCHEMA.to_string(),
            stream_id: "stream-1".to_string(),
            operation_id: OperationId::new("op-1"),
            sequence: DecimalU128::new(sequence),
            cursor,
            emitted_at: format!("2026-08-28T00:00:{:02}Z", sequence - 1),
            monotonic_offset_ns: DecimalU128::new(sequence),
            r#type: event_type,
            phase: EventPhase::Execute,
            payload,
            terminal,
            checkpoint: EventCheckpoint {
                durable,
                last_durable_sequence: DecimalU128::new(sequence),
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn started(cursor: String, sequence: u128) -> EventEnvelope {
        event(
            sequence,
            cursor,
            true,
            EventType::OperationStarted,
            false,
            serde_json::json!({"status":"started"}),
        )
    }

    #[cfg(target_os = "linux")]
    fn progress(cursor: String, sequence: u128) -> EventEnvelope {
        event(
            sequence,
            cursor,
            true,
            EventType::ScanProgress,
            false,
            serde_json::json!({"done": sequence}),
        )
    }

    #[cfg(target_os = "linux")]
    fn terminal(cursor: String, sequence: u128, digest: &str) -> EventEnvelope {
        event(
            sequence,
            cursor,
            true,
            EventType::OperationTerminal,
            true,
            serde_json::to_value(TerminalEventPayload {
                status: OutputStatus::Ok,
                exit_code: ExitCode::Completed,
                kind: OutputKind::ScanResult,
                snapshot_digest: digest.to_string(),
            })
            .unwrap(),
        )
    }

    #[cfg(target_os = "linux")]
    fn snapshot(digest: &str) -> FinalSnapshotMetadata {
        FinalSnapshotMetadata::from_json(&serde_json::json!({
            "schema": "sweepx.operation-snapshot/v1",
            "operationId": "op-1",
            "command": "scan",
            "state": "completed",
            "status": "ok",
            "exitCode": 0,
            "fixtureDigest": digest
        }))
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn next_cursor(journal: &EventJournal, previous_digest: Option<&str>, sequence: u64) -> String {
        let basis = previous_digest.unwrap_or("genesis");
        let nonce = journal.verify_integrity().unwrap().generation_nonce;
        next_durable_cursor("stream-1", "op-1", sequence, &nonce, basis)
    }

    #[cfg(target_os = "linux")]
    fn latest_digest(journal: &EventJournal) -> String {
        let connection = journal.lock_connection().unwrap();
        connection
            .query_row(
                "SELECT digest FROM journal_head WHERE singleton=1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap()
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn append_terminal(journal: &EventJournal, sequence: u64, digest: &str) -> EventEnvelope {
        let snapshot = snapshot(digest);
        let c = next_cursor(journal, Some(&latest_digest(journal)), sequence);
        let e = terminal(c, sequence as u128, &snapshot.snapshot_digest);
        journal
            .append_terminal_with_snapshot(&e, &snapshot)
            .unwrap();
        e
    }

    #[cfg(target_os = "linux")]
    fn unassigned_complete_stream(final_snapshot: &FinalSnapshotMetadata) -> Vec<EventEnvelope> {
        let mut events = vec![
            started("producer-start".to_string(), 1),
            progress("producer-progress".to_string(), 2),
            terminal(
                "producer-terminal".to_string(),
                3,
                final_snapshot.snapshot_digest(),
            ),
        ];
        for event in &mut events {
            event.sequence = DecimalU128::new(99);
            event.checkpoint.durable = false;
            event.checkpoint.last_durable_sequence = DecimalU128::ZERO;
        }
        events
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn happy_replay_and_validate_all() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let position = journal
            .next_append_position("stream-1", "op-1", true)
            .unwrap();
        assert_eq!(position.sequence, 1);
        assert_eq!(position.last_durable_sequence, 1);
        let c1 = position.cursor.as_str().to_string();
        let e1 = started(c1.clone(), 1);
        journal.append_event(&e1).unwrap();
        let progress_position = journal
            .next_append_position("stream-1", "op-1", false)
            .unwrap();
        assert_eq!(progress_position.sequence, 2);
        assert_eq!(progress_position.last_durable_sequence, 1);
        let c2 = next_cursor(&journal, Some("sha256:placeholder-not-used"), 2);
        let e2 = progress(c2.clone(), 2);
        assert!(matches!(
            journal.append_event(&e2),
            Err(JournalError::CursorMismatch)
        ));
        let c2 = next_cursor(&journal, Some(&latest_digest(&journal)), 2);
        let e2 = progress(c2.clone(), 2);
        journal.append_event(&e2).unwrap();
        let terminal = append_terminal(
            &journal,
            3,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let replay = journal
            .snapshot_replay_session()
            .unwrap()
            .replay_from_cursor(None, 10)
            .unwrap();
        assert!(!replay.reset_required);
        assert_eq!(replay.events.len(), 3);
        let all = journal
            .read_all_validated(&TerminalEventExpectation::new(
                OutputStatus::Ok,
                ExitCode::Completed,
                OutputKind::ScanResult,
                terminal.terminal_payload().unwrap().snapshot_digest,
            ))
            .unwrap();
        assert_eq!(all.len(), 3);
        let stored_snapshot = journal.read_final_snapshot().unwrap().unwrap();
        assert_eq!(
            stored_snapshot.snapshot_digest(),
            terminal.terminal_payload().unwrap().snapshot_digest
        );
        assert_eq!(
            sha256_digest(stored_snapshot.canonical_snapshot()),
            stored_snapshot.snapshot_digest()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_append_assigns_positions_and_commits_terminal_snapshot() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let final_snapshot = snapshot("complete-stream");
        let mut events = unassigned_complete_stream(&final_snapshot);

        journal
            .append_complete_stream(&mut events, &final_snapshot)
            .unwrap();

        let mut cursors = std::collections::BTreeSet::new();
        for (index, event) in events.iter().enumerate() {
            let sequence = u128::try_from(index + 1).unwrap();
            assert_eq!(u128::from(event.sequence), sequence);
            assert!(event.cursor.starts_with("sxcur1."));
            assert!(cursors.insert(event.cursor.as_str()));
            assert!(event.checkpoint.durable);
            assert_eq!(u128::from(event.checkpoint.last_durable_sequence), sequence);
        }

        let replay = journal
            .snapshot_replay_session()
            .unwrap()
            .replay_from_cursor(None, 10)
            .unwrap();
        assert!(!replay.reset_required);
        assert_eq!(replay.events, events);
        assert_eq!(
            replay.next_cursor.as_deref(),
            events.last().map(|event| event.cursor.as_str())
        );
        let stored_snapshot = journal.read_final_snapshot().unwrap().unwrap();
        assert_eq!(stored_snapshot, final_snapshot);
        let integrity = journal.verify_integrity().unwrap();
        assert_eq!(integrity.event_count, 3);
        assert_eq!(integrity.latest_sequence, 3);
        assert_eq!(integrity.last_durable_sequence, 3);
        assert_eq!(integrity.terminal_sequence, Some(3));
        assert!(integrity.has_terminal_snapshot());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_session_pages_one_verified_snapshot() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let final_snapshot = snapshot("paged-replay");
        let mut events = unassigned_complete_stream(&final_snapshot);
        journal
            .append_complete_stream(&mut events, &final_snapshot)
            .unwrap();

        let session = journal.snapshot_replay_session().unwrap();
        assert_eq!(session.verified_event_count(), 3);
        assert_eq!(
            session.latest_cursor(),
            events.last().map(|event| event.cursor.as_str())
        );
        assert_eq!(session.integrity().event_count, 3);
        assert_eq!(session.integrity().latest_sequence, 3);
        assert_eq!(session.integrity().terminal_sequence, Some(3));
        let frozen_snapshot = session.final_snapshot().unwrap();
        assert_eq!(frozen_snapshot, &final_snapshot);
        assert_eq!(
            frozen_snapshot.terminal_expectation().exit_code,
            OutputStatus::Ok.into()
        );
        assert_eq!(
            frozen_snapshot.canonical_snapshot(),
            final_snapshot.canonical_snapshot()
        );

        let first = session.replay_from_cursor(None, 1).unwrap();
        assert!(!first.reset_required);
        assert_eq!(first.events, events[0..1]);
        assert_eq!(
            first.next_cursor.as_deref(),
            Some(events[0].cursor.as_str())
        );

        let first_cursor = DurableCursor::parse(first.next_cursor.unwrap()).unwrap();
        let second = session.replay_from_cursor(Some(&first_cursor), 1).unwrap();
        assert!(!second.reset_required);
        assert_eq!(second.events, events[1..2]);
        assert_eq!(
            second.next_cursor.as_deref(),
            Some(events[1].cursor.as_str())
        );

        let second_cursor = DurableCursor::parse(second.next_cursor.unwrap()).unwrap();
        let third = session.replay_from_cursor(Some(&second_cursor), 1).unwrap();
        assert_eq!(third.events, events[2..3]);
        assert_eq!(
            third.next_cursor.as_deref(),
            Some(events[2].cursor.as_str())
        );

        let terminal_cursor = DurableCursor::parse(third.next_cursor.unwrap()).unwrap();
        let exhausted = session
            .replay_from_cursor(Some(&terminal_cursor), 1)
            .unwrap();
        assert!(!exhausted.reset_required);
        assert!(exhausted.events.is_empty());
        assert_eq!(exhausted.next_cursor, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn consuming_replay_yields_bounded_pages_without_empty_tail() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let final_snapshot = snapshot("owned-pages");
        let mut events = Vec::with_capacity(1_026);
        events.push(started("producer-start".to_string(), 1));
        for sequence in 2..=1_025_u128 {
            let mut event = progress(format!("producer-{sequence}"), sequence);
            event.emitted_at = "2026-08-28T00:00:00Z".to_string();
            events.push(event);
        }
        let mut terminal = terminal(
            "producer-terminal".to_string(),
            1_026,
            final_snapshot.snapshot_digest(),
        );
        terminal.emitted_at = "2026-08-28T00:00:00Z".to_string();
        events.push(terminal);
        for event in &mut events {
            event.sequence = DecimalU128::new(99);
            event.checkpoint.durable = false;
            event.checkpoint.last_durable_sequence = DecimalU128::ZERO;
        }
        journal
            .append_complete_stream(&mut events, &final_snapshot)
            .unwrap();

        let after = DurableCursor::parse(events[0].cursor.clone()).unwrap();
        let owned = journal
            .snapshot_replay_session()
            .unwrap()
            .into_replay_pages(Some(&after))
            .unwrap();
        let OwnedReplay::Pages(mut pages) = owned else {
            panic!("known cursor must not reset");
        };
        let first = pages.next().unwrap();
        let second = pages.next().unwrap();
        assert_eq!(first.events.len(), 1_024);
        assert_eq!(second.events.len(), 1);
        assert!(pages.next().is_none());
        assert_eq!(first.events, events[1..1_025]);
        assert_eq!(second.events, events[1_025..]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_session_enforces_page_limit() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let session = journal.snapshot_replay_session().unwrap();

        assert!(matches!(
            session.replay_from_cursor(None, 0),
            Err(JournalError::InvalidReplayLimit)
        ));
        assert!(matches!(
            session.replay_from_cursor(None, 1025),
            Err(JournalError::InvalidReplayLimit)
        ));
        assert!(
            session
                .replay_from_cursor(None, 1)
                .unwrap()
                .events
                .is_empty()
        );
        assert!(
            session
                .replay_from_cursor(None, 1024)
                .unwrap()
                .events
                .is_empty()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_replay_open_never_creates_missing_state() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("missing-journal");
        assert!(matches!(
            EventJournal::open_verified_replay_session(&missing),
            Err(JournalError::StateNotFound)
        ));
        assert!(!missing.exists());
    }

    #[test]
    fn durable_cursor_accepts_the_protocol_maximum_length() {
        let token_len = MAX_CURSOR_BYTES - "sxcur1.".len();
        let cursor = format!("sxcur1.{}", "a".repeat(token_len));
        assert_eq!(cursor.len(), sweepx_protocol::MAX_EVENT_CURSOR_BYTES);
        assert!(DurableCursor::parse(cursor).is_ok());
        assert!(matches!(
            DurableCursor::parse(format!("sxcur1.{}", "a".repeat(token_len + 1))),
            Err(JournalError::MalformedCursor)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_session_never_follows_later_appends() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let first_cursor = next_cursor(&journal, None, 1);
        let first_event = started(first_cursor.clone(), 1);
        journal.append_event(&first_event).unwrap();
        let session = journal.snapshot_replay_session().unwrap();

        let second_cursor = next_cursor(&journal, Some(&latest_digest(&journal)), 2);
        let second_event = progress(second_cursor, 2);
        journal.append_event(&second_event).unwrap();

        assert_eq!(
            session.replay_from_cursor(None, 1024).unwrap().events,
            vec![first_event]
        );
        let first_cursor = DurableCursor::parse(first_cursor).unwrap();
        let exhausted = session
            .replay_from_cursor(Some(&first_cursor), 1024)
            .unwrap();
        assert!(!exhausted.reset_required);
        assert!(exhausted.events.is_empty());

        let refreshed = journal.snapshot_replay_session().unwrap();
        assert_eq!(
            refreshed
                .replay_from_cursor(Some(&first_cursor), 1024)
                .unwrap()
                .events,
            vec![second_event]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replay_session_open_fails_closed_on_cursor_index_corruption() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let first_cursor = next_cursor(&journal, None, 1);
        journal.append_event(&started(first_cursor, 1)).unwrap();
        assert!(
            journal
                .snapshot_replay_session()
                .unwrap()
                .final_snapshot()
                .is_none()
        );
        {
            let connection = journal.lock_connection().unwrap();
            connection
                .execute("UPDATE durable_cursors SET digest='sha256:tampered'", [])
                .unwrap();
        }

        assert!(matches!(
            journal.snapshot_replay_session(),
            Err(JournalError::TamperDetected)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_validation_failure_keeps_journal_and_input_unchanged() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let final_snapshot = snapshot("invalid-midstream");
        let mut events = unassigned_complete_stream(&final_snapshot);
        events[1].stream_id = "different-stream".to_string();
        let original = events.clone();

        assert!(matches!(
            journal.append_complete_stream(&mut events, &final_snapshot),
            Err(JournalError::ProtocolValidation(message))
                if message.contains("streamId changes at index 1")
        ));
        assert_eq!(events, original);
        assert_eq!(journal.verify_integrity().unwrap().event_count, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_sqlite_failure_rolls_back_every_insert() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let final_snapshot = snapshot("forced-rollback");
        let mut events = unassigned_complete_stream(&final_snapshot);
        let original = events.clone();
        {
            let connection = journal.lock_connection().unwrap();
            connection
                .execute_batch(
                    "CREATE TEMP TRIGGER fail_second_batch_insert BEFORE INSERT ON journal_events WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'forced batch failure'); END;",
                )
                .unwrap();
        }

        assert!(matches!(
            journal.append_complete_stream(&mut events, &final_snapshot),
            Err(JournalError::Database(_))
        ));
        assert_eq!(events, original);
        let integrity = journal.verify_integrity().unwrap();
        assert_eq!(integrity.event_count, 0);
        assert_eq!(integrity.terminal_sequence, None);
        assert_eq!(journal.read_final_snapshot().unwrap(), None);
        let connection = journal.lock_connection().unwrap();
        let cursor_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM durable_cursors", [], |row| row.get(0))
            .unwrap();
        assert_eq!(cursor_count, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_requires_empty_journal() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let cursor = next_cursor(&journal, None, 1);
        journal.append_event(&started(cursor, 1)).unwrap();
        let final_snapshot = snapshot("nonempty");
        let mut events = unassigned_complete_stream(&final_snapshot);
        let original = events.clone();

        assert!(matches!(
            journal.append_complete_stream(&mut events, &final_snapshot),
            Err(JournalError::JournalNotEmpty)
        ));
        assert_eq!(events, original);
        let integrity = journal.verify_integrity().unwrap();
        assert_eq!(integrity.event_count, 1);
        assert_eq!(integrity.terminal_sequence, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_rejects_terminal_snapshot_mismatch_atomically() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let event_snapshot = snapshot("event-terminal");
        let persisted_snapshot = snapshot("persisted-terminal");
        let mut events = unassigned_complete_stream(&event_snapshot);
        let original = events.clone();

        assert!(matches!(
            journal.append_complete_stream(&mut events, &persisted_snapshot),
            Err(JournalError::TerminalMetadataMismatch)
        ));
        assert_eq!(events, original);
        assert_eq!(journal.verify_integrity().unwrap().event_count, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_count_and_aggregate_size_are_bounded() {
        assert!(matches!(
            ensure_complete_stream_event_count(0),
            Err(JournalError::ProtocolValidation(_))
        ));
        assert!(matches!(
            ensure_complete_stream_event_count(MAX_EVENTS as usize + 1),
            Err(JournalError::EventLimitExceeded)
        ));
        let maximum_payload = (MAX_DATABASE_BYTES - MAX_APPEND_RESERVE_BYTES) as usize;
        assert_eq!(
            checked_complete_stream_payload_bytes(
                maximum_payload - MAX_BATCH_STORAGE_OVERHEAD_PER_EVENT - 1,
                1
            )
            .unwrap(),
            maximum_payload
        );
        assert!(matches!(
            checked_complete_stream_payload_bytes(
                maximum_payload - MAX_BATCH_STORAGE_OVERHEAD_PER_EVENT,
                1
            ),
            Err(JournalError::QuotaExceeded)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sqlite_full_is_reported_as_journal_quota() {
        let sqlite = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some("database or disk is full".to_string()),
        );
        assert!(matches!(
            map_sqlite_quota_error(sqlite),
            JournalError::QuotaExceeded
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_api_rejects_too_many_events_without_side_effects() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let final_snapshot = snapshot("event-limit");
        let template = progress("producer-position".to_string(), 7);
        let mut events = vec![template; MAX_EVENTS as usize + 1];
        let first_before = events.first().unwrap().clone();
        let last_before = events.last().unwrap().clone();

        assert!(matches!(
            journal.append_complete_stream(&mut events, &final_snapshot),
            Err(JournalError::EventLimitExceeded)
        ));
        assert_eq!(events.first(), Some(&first_before));
        assert_eq!(events.last(), Some(&last_before));
        assert_eq!(journal.verify_integrity().unwrap().event_count, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn complete_stream_api_rejects_aggregate_quota_without_side_effects() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let final_snapshot = snapshot("aggregate-quota");
        let mut events = Vec::with_capacity(130);
        events.push(started("producer-start".to_string(), 1));
        for sequence in 2..130_u128 {
            let mut event = progress("producer-progress".to_string(), sequence);
            event.emitted_at = "2026-08-28T00:00:01Z".to_string();
            event.payload = serde_json::json!({ "blob": "x".repeat(250 * 1024) });
            events.push(event);
        }
        events.push(terminal(
            "producer-terminal".to_string(),
            130,
            final_snapshot.snapshot_digest(),
        ));
        events.last_mut().unwrap().emitted_at = "2026-08-28T00:00:02Z".to_string();
        for event in &mut events {
            event.sequence = DecimalU128::new(999);
            event.checkpoint.durable = false;
            event.checkpoint.last_durable_sequence = DecimalU128::ZERO;
        }
        let first_before = events.first().unwrap().clone();
        let last_before = events.last().unwrap().clone();

        assert!(matches!(
            journal.append_complete_stream(&mut events, &final_snapshot),
            Err(JournalError::QuotaExceeded)
        ));
        assert_eq!(events.first(), Some(&first_before));
        assert_eq!(events.last(), Some(&last_before));
        let integrity = journal.verify_integrity().unwrap();
        assert_eq!(integrity.event_count, 0);
        assert_eq!(integrity.latest_cursor, None);
        assert_eq!(journal.read_final_snapshot().unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_well_formed_cursor_requires_snapshot_reset() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let cursor = DurableCursor::parse("sxcur1.unknown-token-000").unwrap();
        let replay = journal
            .snapshot_replay_session()
            .unwrap()
            .replay_from_cursor(Some(&cursor), 10)
            .unwrap();
        assert!(replay.reset_required);
        assert!(replay.events.is_empty());
        assert!(replay.next_cursor.is_none());
        assert!(matches!(
            DurableCursor::parse("sxcur1.bad/path token"),
            Err(JournalError::MalformedCursor)
        ));
    }

    #[test]
    fn malformed_cursor_is_distinct_from_unknown_cursor() {
        assert!(matches!(
            DurableCursor::parse("not-a-durable-cursor"),
            Err(JournalError::MalformedCursor)
        ));
        assert!(matches!(
            DurableCursor::parse("sxcur1.short"),
            Err(JournalError::MalformedCursor)
        ));
        assert!(matches!(
            DurableCursor::parse("sxcur1.bad/path token"),
            Err(JournalError::MalformedCursor)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn append_enforces_started_checkpoint_and_time_continuity() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let first_cursor = next_cursor(&journal, None, 1);
        assert!(matches!(
            journal.append_event(&progress(first_cursor.clone(), 1)),
            Err(JournalError::FirstEventNotStarted)
        ));
        journal.append_event(&started(first_cursor, 1)).unwrap();

        let c2 = next_cursor(&journal, Some(&latest_digest(&journal)), 2);
        assert!(matches!(
            journal.append_event(&started(c2.clone(), 2)),
            Err(JournalError::StartedEventRepeated)
        ));

        let mut bad_checkpoint = progress(c2.clone(), 2);
        bad_checkpoint.checkpoint.durable = false;
        bad_checkpoint.checkpoint.last_durable_sequence = DecimalU128::ZERO;
        assert!(matches!(
            journal.append_event(&bad_checkpoint),
            Err(JournalError::CheckpointMismatch)
        ));

        let mut regressed = progress(c2, 2);
        regressed.emitted_at = "2026-08-27T23:59:59Z".to_string();
        assert!(matches!(
            journal.append_event(&regressed),
            Err(JournalError::TimeRegression)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_rejects_dropped_append_only_trigger() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        drop(journal);
        let connection = Connection::open(root.join(DATABASE_FILE)).unwrap();
        connection
            .execute_batch("DROP TRIGGER journal_events_no_update;")
            .unwrap();
        drop(connection);

        assert!(matches!(
            EventJournal::open(&root),
            Err(JournalError::DatabaseConfiguration(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn one_journal_owner_excludes_a_second_writer() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let first = EventJournal::open(&root).unwrap();
        assert!(matches!(
            EventJournal::open(&root),
            Err(JournalError::ConcurrentWriterDenied)
        ));
        drop(first);
        EventJournal::open(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn committed_event_survives_abrupt_process_exit() {
        const CHILD_ENV: &str = "SWEEPX_EVENT_JOURNAL_CRASH_CHILD";
        const ROOT_ENV: &str = "SWEEPX_EVENT_JOURNAL_CRASH_ROOT";
        if std::env::var_os(CHILD_ENV).is_some() {
            let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
            let journal = EventJournal::open(&root).unwrap();
            let position = journal
                .next_append_position("stream-1", "op-1", true)
                .unwrap();
            journal
                .append_event(&started(position.cursor.as_str().to_string(), 1))
                .unwrap();
            std::process::abort();
        }

        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::committed_event_survives_abrupt_process_exit")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .env(ROOT_ENV, &root)
            .status()
            .unwrap();
        assert!(!status.success());

        let journal = EventJournal::open(&root).unwrap();
        let integrity = journal.verify_integrity().unwrap();
        assert_eq!(integrity.event_count, 1);
        assert_eq!(integrity.latest_sequence, 1);
        assert_eq!(integrity.last_durable_sequence, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_rejects_unsafe_sidecars_and_oversized_state() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        drop(EventJournal::open(&root).unwrap());
        let external = temp.path().join("external");
        File::create(&external).unwrap();
        symlink(&external, root.join(format!("{DATABASE_FILE}-wal"))).unwrap();
        assert!(matches!(
            EventJournal::open(&root),
            Err(JournalError::SymlinkRejected(_))
        ));
        fs::remove_file(root.join(format!("{DATABASE_FILE}-wal"))).unwrap();

        let wal = root.join(format!("{DATABASE_FILE}-wal"));
        let file = File::create(&wal).unwrap();
        file.set_len(MAX_WAL_BYTES + 1).unwrap();
        fs::set_permissions(&wal, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            EventJournal::open(&root),
            Err(JournalError::QuotaExceeded)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn active_journal_rejects_root_and_database_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let moved = temp.path().join("moved-journal");
        fs::rename(&root, &moved).unwrap();
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        assert!(matches!(
            journal.verify_integrity(),
            Err(JournalError::StateIdentityChanged)
        ));
        drop(journal);

        fs::remove_dir(&root).unwrap();
        fs::rename(&moved, &root).unwrap();
        let journal = EventJournal::open(&root).unwrap();
        let replacement = root.join("replacement.db");
        fs::write(&replacement, b"not sqlite").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, root.join(DATABASE_FILE)).unwrap();
        assert!(matches!(
            journal.verify_integrity(),
            Err(JournalError::StateIdentityChanged)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journal_generation_changes_first_cursor_after_rebuild() {
        let temp = TempDir::new().unwrap();
        let first_root = private_root(&temp);
        let first = EventJournal::open(&first_root).unwrap();
        let first_position = first
            .next_append_position("stream-1", "op-1", true)
            .unwrap();
        let first_cursor = first_position.cursor.clone();
        first
            .append_event(&started(first_cursor.as_str().to_string(), 1))
            .unwrap();
        drop(first);

        let second_root = temp.path().join("second-journal");
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&second_root)
            .unwrap();
        let second = EventJournal::open(&second_root).unwrap();
        let final_snapshot = snapshot("second-generation");
        let mut events = unassigned_complete_stream(&final_snapshot);
        second
            .append_complete_stream(&mut events, &final_snapshot)
            .unwrap();
        let second_cursor = events[0].cursor.clone();
        let latest_cursor = events.last().unwrap().cursor.clone();
        assert_ne!(first_cursor.as_str(), second_cursor);
        let session = second.snapshot_replay_session().unwrap();
        let replay = session.replay_from_cursor(Some(&first_cursor), 8).unwrap();
        assert!(replay.reset_required);
        assert!(replay.events.is_empty());
        assert_eq!(replay.next_cursor, Some(latest_cursor));
        let resume = session
            .replay_from_cursor(
                Some(
                    &DurableCursor::parse(replay.next_cursor.unwrap())
                        .expect("journal-issued reset cursor is valid"),
                ),
                8,
            )
            .unwrap();
        assert!(!resume.reset_required);
        assert!(resume.events.is_empty());
        assert!(resume.next_cursor.is_none());
        assert_eq!(
            second.read_final_snapshot().unwrap().unwrap(),
            final_snapshot
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn terminal_snapshot_semantics_must_match_the_event() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let c1 = next_cursor(&journal, None, 1);
        journal.append_event(&started(c1, 1)).unwrap();
        let snapshot = FinalSnapshotMetadata::from_json(&serde_json::json!({
            "schema": "sweepx.operation-snapshot/v1",
            "operationId": "op-1",
            "command": "scan",
            "state": "failed",
            "status": "failed",
            "exitCode": 8
        }))
        .unwrap();
        let c2 = next_cursor(&journal, Some(&latest_digest(&journal)), 2);
        let contradictory = terminal(c2, 2, snapshot.snapshot_digest());
        assert!(matches!(
            journal.append_terminal_with_snapshot(&contradictory, &snapshot),
            Err(JournalError::TerminalMetadataMismatch)
        ));
        assert_eq!(journal.verify_integrity().unwrap().event_count, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn duplicate_terminal_and_post_terminal_are_rejected() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let c1 = next_cursor(&journal, None, 1);
        journal.append_event(&started(c1, 1)).unwrap();
        append_terminal(
            &journal,
            2,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let c3 = next_cursor(&journal, Some(&latest_digest(&journal)), 3);
        assert!(matches!(
            journal.append_event(&progress(c3, 3)),
            Err(JournalError::AlreadyTerminal)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn payload_quota_and_corruption_are_detected() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let large_payload = serde_json::Value::String("x".repeat(MAX_EVENT_BYTES + 1));
        let event = EventEnvelope {
            schema: sweepx_protocol::EVENT_SCHEMA.to_string(),
            stream_id: "stream-1".to_string(),
            operation_id: OperationId::new("op-1"),
            sequence: DecimalU128::new(1),
            cursor: next_cursor(&journal, None, 1),
            emitted_at: "2026-08-28T00:00:00Z".to_string(),
            monotonic_offset_ns: DecimalU128::new(1),
            r#type: EventType::OperationStarted,
            phase: EventPhase::Execute,
            payload: serde_json::json!({ "blob": large_payload }),
            terminal: false,
            checkpoint: EventCheckpoint {
                durable: true,
                last_durable_sequence: DecimalU128::new(1),
            },
        };
        assert!(matches!(
            journal.append_event(&event),
            Err(JournalError::ProtocolValidation(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_rejection_and_atomic_terminal_rollback() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let target = temp.path().join("external");
        File::create(&target).unwrap();
        symlink(&target, root.join(DATABASE_FILE)).unwrap();
        assert!(matches!(
            EventJournal::open(&root),
            Err(JournalError::SymlinkRejected(_))
        ));

        let root = temp.path().join("good");
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let journal = EventJournal::open(&root).unwrap();
        let c1 = next_cursor(&journal, None, 1);
        journal.append_event(&started(c1, 1)).unwrap();
        let c2 = next_cursor(&journal, Some(&latest_digest(&journal)), 2);
        let bad_terminal = terminal(
            c2,
            2,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );
        assert!(matches!(
            journal.append_terminal_with_snapshot(
                &bad_terminal,
                &FinalSnapshotMetadata::from_json(&serde_json::json!({
                    "schema": "sweepx.operation-snapshot/v1",
                    "operationId": "op-1",
                    "command": "scan",
                    "state": "completed",
                    "status": "ok",
                    "exitCode": 0
                }))
                .unwrap(),
            ),
            Err(JournalError::TerminalMetadataMismatch)
        ));
        let integrity = journal.verify_integrity().unwrap();
        assert_eq!(integrity.event_count, 1);
        assert_eq!(integrity.terminal_sequence, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tamper_and_reset_required_fail_closed() {
        let temp = TempDir::new().unwrap();
        let root = private_root(&temp);
        let journal = EventJournal::open(&root).unwrap();
        let c1 = next_cursor(&journal, None, 1);
        journal.append_event(&started(c1, 1)).unwrap();
        append_terminal(
            &journal,
            2,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        let cursor =
            DurableCursor::parse(journal.verify_integrity().unwrap().latest_cursor.unwrap())
                .unwrap();
        let replay = journal
            .snapshot_replay_session()
            .unwrap()
            .replay_from_cursor(Some(&cursor), 10)
            .unwrap();
        assert!(!replay.reset_required);
        assert!(replay.events.is_empty());
        drop(journal);

        let connection = Connection::open(root.join(DATABASE_FILE)).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER journal_events_no_update; UPDATE journal_events SET digest='sha256:tampered' WHERE sequence=1;",
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            EventJournal::open(&root),
            Err(JournalError::TamperDetected | JournalError::DatabaseConfiguration(_))
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_never_creates_state() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("journal");
        let error = EventJournal::open(&root).unwrap_err();
        assert!(matches!(error, JournalError::Unsupported));
        assert!(!root.exists());
    }
}
