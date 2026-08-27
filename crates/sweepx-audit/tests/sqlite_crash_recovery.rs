#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, params};
use sweepx_audit::{
    ActionId, AuditError, AuditStore, AuthorizationBinding, AuthorizationId, AuthorizationSource,
    BatchId, DigestString, HostId, IntentRequest, IntentReservation, ItemId, PathHash, PlanId,
    RegisterAuthorization, RequestedMode, RiskTier, SessionId, UserId,
};
use sweepx_protocol::{AuditProjectionState, AuditRecoveryDisposition};
use tempfile::TempDir;

const CHILD_ENV: &str = "SWEEPX_AUDIT_CRASH_CHILD";
const ROOT_ENV: &str = "SWEEPX_AUDIT_CRASH_ROOT";
const READY_FILE: &str = "child-ready";
const DATABASE_FILE: &str = "audit.db";
const WAL_FILE: &str = "audit.db-wal";

fn binding() -> AuthorizationBinding {
    let item_id = ItemId::new("item-crash-integration").unwrap();
    let action_id = ActionId::new("action-crash-integration").unwrap();
    AuthorizationBinding {
        authorization_id: AuthorizationId::new("authorization-crash-integration").unwrap(),
        authorization_source: AuthorizationSource::DeterministicSimulation,
        batch_id: BatchId::new("batch-crash-integration").unwrap(),
        plan_id: PlanId::new("plan-crash-integration").unwrap(),
        plan_digest: DigestString::new("plan-digest-crash-integration").unwrap(),
        requested_mode: RequestedMode::Permanent,
        item_ids: BTreeSet::from([item_id.clone()]),
        action_ids: BTreeSet::from([action_id.clone()]),
        action_count: 1,
        item_by_action: BTreeMap::from([(action_id.clone(), item_id)]),
        risk_by_action: BTreeMap::from([(action_id, RiskTier::R4)]),
        policy_version: "policy-v1".to_string(),
        policy_digest: DigestString::new("policy-digest-crash-integration").unwrap(),
        protected_anchor_snapshot_digest: DigestString::new("anchor-digest-crash-integration")
            .unwrap(),
        adapter_capabilities_digest: DigestString::new("adapter-digest-crash-integration").unwrap(),
        cleaner_set_digest: DigestString::new("cleaner-digest-crash-integration").unwrap(),
        host_instance_id: HostId::new("host-crash-integration").unwrap(),
        user_identity: UserId::new("user-crash-integration").unwrap(),
        workflow_session: SessionId::new("session-crash-integration").unwrap(),
    }
}

fn intent_request() -> IntentRequest {
    IntentRequest {
        item_id: ItemId::new("item-crash-integration").unwrap(),
        action_id: ActionId::new("action-crash-integration").unwrap(),
        source_path_hash: PathHash::new("source-path-crash-integration").unwrap(),
        before_revalidation_digest: DigestString::new("revalidation-crash-integration").unwrap(),
    }
}

fn register(store: &AuditStore, binding: &AuthorizationBinding) {
    store
        .register_authorization(RegisterAuthorization {
            binding: binding.clone(),
        })
        .unwrap();
}

fn private_root(temp: &TempDir) -> PathBuf {
    let root = temp.path().join("audit");
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    root
}

fn spawn_child(root: &Path, scenario: &str) -> std::process::Child {
    Command::new(env::current_exe().unwrap())
        .arg("--exact")
        .arg("crash_child")
        .arg("--nocapture")
        .env(CHILD_ENV, scenario)
        .env(ROOT_ENV, root)
        .spawn()
        .unwrap()
}

fn wait_until_ready(root: &Path, child: &mut std::process::Child) {
    let ready = root.join(READY_FILE);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if ready.exists() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("crash child exited before its barrier: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for crash child barrier"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn kill_and_wait(child: &mut std::process::Child) -> ExitStatus {
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    status
}

fn raw_connection(root: &Path) -> Connection {
    let connection = Connection::open_with_flags(
        root.join(DATABASE_FILE),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    connection.busy_timeout(Duration::ZERO).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA mmap_size=0; \
             PRAGMA trusted_schema=OFF; PRAGMA read_uncommitted=OFF; \
             PRAGMA locking_mode=NORMAL; PRAGMA temp_store=MEMORY;",
        )
        .unwrap();
    let journal: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
        .unwrap();
    assert_eq!(journal.to_ascii_lowercase(), "wal");
    connection
}

fn committed_intent_child(root: &Path) -> ! {
    let store = AuditStore::open(root).unwrap();
    let binding = binding();
    register(&store, &binding);

    let checkpoint = raw_connection(root);
    let (busy, _, _): (i64, i64, i64) = checkpoint
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(busy, 0);
    drop(checkpoint);

    // Pin the pre-commit database end-mark so the committed intent remains in a
    // live WAL rather than being checkpointed into the main database.
    let reader = raw_connection(root);
    reader.execute_batch("BEGIN").unwrap();
    let _: i64 = reader
        .query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))
        .unwrap();

    let claim = store
        .claim_execution(&binding.authorization_id, &binding.plan_digest)
        .unwrap();
    let token = store.reserve_intent(&claim, intent_request()).unwrap();
    assert_eq!(token.action_id().as_str(), "action-crash-integration");
    assert!(root.join(WAL_FILE).metadata().unwrap().len() > 0);
    fs::write(root.join(READY_FILE), b"intent-committed\n").unwrap();
    loop {
        thread::park();
    }
}

fn uncommitted_transaction_child(root: &Path) -> ! {
    let connection = raw_connection(root);
    let (busy, _, _): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(busy, 0);
    let wal_len_before = root
        .join(WAL_FILE)
        .metadata()
        .map_or(0, |metadata| metadata.len());
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    connection
        .execute(
            "INSERT INTO executions(
                execution_id,authorization_id,fence_epoch,kind,state,started_at_ms
             ) VALUES('execution-uncommitted-crash',?1,99,'execution','active',1)",
            ["authorization-crash-integration"],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE authorizations SET
                state='claimed',current_fence_epoch=99,
                current_execution_id='execution-uncommitted-crash'
             WHERE authorization_id=?1",
            ["authorization-crash-integration"],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE store_meta SET next_fence_epoch=99,next_attempt_ordinal=1 WHERE singleton=1",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO audit_events( \
                sequence,recorded_at_ms,monotonic_elapsed_ns,kind,authorization_id,action_id, \
                attempt_id,previous_digest,payload_json,digest \
             ) VALUES(2,1,'0','action_intent',?1,?2,'attempt-uncommitted-crash',NULL,'{}','sha256:uncommitted')",
            params![
                "authorization-crash-integration",
                "action-crash-integration"
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE audit_head SET sequence=2,digest='sha256:uncommitted' WHERE singleton=1",
            [],
        )
        .unwrap();

    // sqlite3_db_cacheflush writes dirty transaction pages to WAL without
    // committing them. SIGKILL must leave those frames invisible on reopen.
    connection.cache_flush().unwrap();
    let wal_path = root.join(WAL_FILE);
    let wal_len_after = wal_path.metadata().unwrap().len();
    assert!(wal_len_after > wal_len_before);
    File::open(&wal_path).unwrap().sync_all().unwrap();
    fs::write(root.join(READY_FILE), b"transaction-uncommitted\n").unwrap();
    loop {
        thread::park();
    }
}

#[test]
fn crash_child() {
    let Ok(scenario) = env::var(CHILD_ENV) else {
        return;
    };
    let root = PathBuf::from(env::var_os(ROOT_ENV).expect("missing child audit root"));
    match scenario.as_str() {
        "committed-intent" => committed_intent_child(&root),
        "uncommitted-transaction" => uncommitted_transaction_child(&root),
        other => panic!("unknown crash scenario {other}"),
    }
}

#[test]
fn committed_intent_survives_sigkill_and_forces_recovery_without_resubmit() {
    let temp = TempDir::new().unwrap();
    let root = private_root(&temp);
    let mut child = spawn_child(&root, "committed-intent");
    wait_until_ready(&root, &mut child);
    assert!(root.join(WAL_FILE).metadata().unwrap().len() > 0);
    let status = kill_and_wait(&mut child);
    assert!(!status.success());
    assert!(root.join(WAL_FILE).metadata().unwrap().len() > 0);

    // The main database was checkpointed immediately before claim/reserve. Its
    // standalone image therefore contains registration only; sequences 2-3
    // exist solely in the committed WAL that AuditStore must recover.
    let main_only = temp.path().join("main-db-without-wal.sqlite");
    fs::copy(root.join(DATABASE_FILE), &main_only).unwrap();
    let main_only_connection = Connection::open(main_only).unwrap();
    let main_only_sequence: i64 = main_only_connection
        .query_row(
            "SELECT sequence FROM audit_head WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(main_only_sequence, 1);
    drop(main_only_connection);

    // Opening the store performs SQLite hot-WAL recovery and then verifies the
    // complete event chain against the relational projection.
    let store = AuditStore::open(&root).unwrap();
    let summary = store.verify_integrity().unwrap();
    assert_eq!(summary.latest_sequence, 3);
    assert_eq!(summary.action_sequence, 1);

    let binding = binding();
    assert!(matches!(
        store.claim_execution(&binding.authorization_id, &binding.plan_digest),
        Err(AuditError::AuthorizationAlreadyClaimed(_))
    ));

    let recovery = store
        .claim_recovery(&binding.authorization_id, &binding.plan_digest)
        .unwrap();
    let unresolved = store.unresolved_recovery_intents(&recovery).unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(
        unresolved[0].action_id().as_str(),
        "action-crash-integration"
    );

    // The strict submission reservation API refuses to mint a new token for
    // the already-durable action, so callers must reconcile the original attempt.
    assert!(matches!(
        store.reserve_intent(&recovery, intent_request()),
        Err(AuditError::ActionAlreadyReserved(ref action))
            if action == "action-crash-integration"
    ));
    assert!(matches!(
        store.reserve_intent_once(&recovery, intent_request()).unwrap(),
        IntentReservation::Existing(ref info)
            if info.attempt_id() == unresolved[0].attempt_id()
    ));
    assert!(matches!(
        store.consume_execution(&recovery),
        Err(AuditError::UnresolvedIntentsRemain)
    ));
}

#[test]
fn sigkill_during_uncommitted_transaction_leaves_no_projection_or_event_fragment() {
    let temp = TempDir::new().unwrap();
    let root = private_root(&temp);
    let binding = binding();
    let store = AuditStore::open(&root).unwrap();
    register(&store, &binding);
    let before = store.verify_integrity().unwrap();
    assert_eq!(before.latest_sequence, 1);
    drop(store);

    let mut child = spawn_child(&root, "uncommitted-transaction");
    wait_until_ready(&root, &mut child);
    assert!(root.join(WAL_FILE).metadata().unwrap().len() > 0);
    let status = kill_and_wait(&mut child);
    assert!(!status.success());
    assert!(root.join(WAL_FILE).metadata().unwrap().len() > 0);

    let store = AuditStore::open(&root).unwrap();
    let after = store.verify_integrity().unwrap();
    assert_eq!(after, before);

    // Neither the projection mutation nor the fabricated event/head update
    // escaped the killed transaction. The original authorization is claimable.
    let connection = raw_connection(&root);
    let meta: (i64, i64) = connection
        .query_row(
            "SELECT next_fence_epoch,next_attempt_ordinal FROM store_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let authorization_state: (String, Option<i64>, Option<String>) = connection
        .query_row(
            "SELECT state,current_fence_epoch,current_execution_id
             FROM authorizations WHERE authorization_id=?1",
            [binding.authorization_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let uncommitted_executions: i64 = connection
        .query_row(
            "SELECT count(*) FROM executions WHERE execution_id='execution-uncommitted-crash'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let uncommitted_events: i64 = connection
        .query_row(
            "SELECT count(*) FROM audit_events WHERE attempt_id='attempt-uncommitted-crash'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(meta, (0, 0));
    assert_eq!(authorization_state, ("unused".to_string(), None, None));
    assert_eq!(uncommitted_executions, 0);
    assert_eq!(uncommitted_events, 0);
    drop(connection);

    let claim = store
        .claim_execution(&binding.authorization_id, &binding.plan_digest)
        .unwrap();
    assert_eq!(claim.fence_epoch(), 1);
}

#[test]
fn reopened_store_projection_marks_committed_intent_as_pending_reconciliation() {
    let temp = TempDir::new().unwrap();
    let root = private_root(&temp);
    let mut child = spawn_child(&root, "committed-intent");
    wait_until_ready(&root, &mut child);
    let status = kill_and_wait(&mut child);
    assert!(!status.success());

    let store = AuditStore::open(&root).unwrap();
    let snapshot = store.projection_snapshot().unwrap();
    assert_eq!(snapshot.batches.len(), 1);
    let batch = &snapshot.batches[0];
    assert_eq!(batch.state, AuditProjectionState::Pending);
    assert!(batch.needs_reconciliation);
    assert_eq!(batch.items.len(), 1);
    assert_eq!(batch.items[0].authorizations.len(), 1);
    assert_eq!(batch.items[0].authorizations[0].actions.len(), 1);
    assert_eq!(
        batch.items[0].authorizations[0].actions[0].state,
        AuditProjectionState::Pending
    );
    assert!(batch.items[0].authorizations[0].actions[0].needs_reconciliation);
    assert_eq!(
        batch.items[0].authorizations[0].actions[0].recovery_disposition,
        None
    );

    let binding = binding();
    let recovery = store
        .claim_recovery(&binding.authorization_id, &binding.plan_digest)
        .unwrap();
    let records = store
        .classify_recovery(&recovery, &struct_pending_observer())
        .unwrap();
    assert_eq!(records.len(), 1);
    let snapshot = store.projection_snapshot().unwrap();
    assert_eq!(
        snapshot.batches[0].items[0].authorizations[0].actions[0].recovery_disposition,
        Some(AuditRecoveryDisposition::Indeterminate)
    );
}

fn struct_pending_observer() -> impl sweepx_audit::RecoveryObserver {
    struct PendingObserver;
    impl sweepx_audit::RecoveryObserver for PendingObserver {
        fn observe(
            &self,
            _intent: &sweepx_audit::RecoveryIntentView,
        ) -> Result<sweepx_audit::RecoveryObservation, sweepx_audit::AuditError> {
            Ok(
                sweepx_audit::RecoveryObservation::SourceAbsentDestinationConfirmed {
                    destination: sweepx_audit::Observation {
                        exists: true,
                        identity: Some("recovered-trash-object".to_string()),
                    },
                },
            )
        }
    }
    PendingObserver
}
