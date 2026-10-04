//! Shared-state admission observed through ordinary metadata/bytes and independent flock FDs.

use super::tests::{binding, permanent_success, register, reserve};
use super::*;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use sweepx_cache::native::Directory;
use sweepx_cache::state_directory::StateWriteSession;

fn fixture() -> (tempfile::TempDir, PathBuf, Directory) {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().canonicalize().unwrap().join("state");
    let directory = Directory::open(&state, true).unwrap();
    (temp, state, directory)
}

fn sparse(root: &Directory, path: &Path, bytes: u64) {
    let file = match root.create_state_file("unknown-note") {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
            .write(true)
            .open(path.join("unknown-note"))
            .unwrap(),
        Err(error) => panic!("sparse setup: {error}"),
    };
    file.set_len(bytes).unwrap();
    assert_eq!(
        fs::symlink_metadata(path.join("unknown-note"))
            .unwrap()
            .len(),
        bytes
    );
}

fn control_held(state: &Path, held: bool) {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(state.join(".lock"))
        .unwrap();
    // Independent ordinary FD and kernel operation; no production guard's fields/flags.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if held {
        assert_eq!(result, -1);
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
    } else {
        assert_eq!(result, 0);
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
    }
}

#[test]
fn bootstrap_reserves_peak_before_mkdir_and_reopen_charges_only_remaining_growth() {
    let (_temp, state, directory) = fixture();
    sparse(&directory, &state, 432 * 1024 * 1024);
    assert!(matches!(
        AuditStore::open_in_state_dir(&state, AuditNamespace::General),
        Err(AuditError::StateResourceLimit {
            resource: "state_bytes",
            limit: 536_870_912
        })
    ));
    assert!(!state.join("audit").exists());
    assert_eq!(fs::read_dir(&state).unwrap().count(), 2); // unknown file + zero bootstrap control
    sparse(&directory, &state, 431 * 1024 * 1024);
    let first = AuditStore::open_in_state_dir(&state, AuditNamespace::General).unwrap();
    let second = AuditStore::open_in_state_dir(&state, AuditNamespace::General).unwrap();
    assert_eq!(first.database_identity, second.database_identity);
    second.verify_integrity().unwrap();
    assert_eq!(
        fs::symlink_metadata(state.join("unknown-note"))
            .unwrap()
            .len(),
        451_936_256
    );
    control_held(&state, false);
}

#[test]
fn bootstrap_accounts_all_six_future_names_at_literal_entry_boundary() {
    let (_temp, state, directory) = fixture();
    for index in 0..4084 {
        drop(
            directory
                .create_state_file(&format!("unknown-{index}"))
                .unwrap(),
        );
    }
    assert!(matches!(
        AuditStore::open_in_state_dir(&state, AuditNamespace::General),
        Err(AuditError::StateResourceLimit {
            resource: "state_entries",
            limit: 4090
        })
    ));
    assert!(!state.join("audit").exists());
    assert_eq!(fs::read_dir(&state).unwrap().count(), 4085);
    // Remove only this controlled empty fixture, never a production eviction.
    fs::remove_file(state.join("unknown-4083")).unwrap();
    let store = AuditStore::open_in_state_dir(&state, AuditNamespace::General).unwrap();
    let authorization = binding(71, RequestedMode::Permanent);
    register(&store, &authorization); // real WAL/index names fit the reserved boundary
    store.verify_integrity().unwrap();
}

#[test]
fn live_claim_preserves_state_exclusion_through_sql_close_consume_drop_and_observer() {
    let (_temp, state, _directory) = fixture();
    let store = AuditStore::open_in_state_dir(&state, AuditNamespace::PermanentDelete).unwrap();
    let authorization = binding(72, RequestedMode::Permanent);
    register(&store, &authorization);
    control_held(&state, false);
    let claim = store
        .claim_execution(&authorization.authorization_id, &authorization.plan_digest)
        .unwrap();
    control_held(&state, true);
    let token = reserve(&store, &claim, &authorization);
    token.validate_current_process().unwrap();
    store.projection_snapshot().unwrap();
    store
        .record_outcome(&claim, &token, permanent_success())
        .unwrap();
    let during_close = state.clone();
    native_state::AFTER_DATABASE_CLOSE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || control_held(&during_close, true)));
    });
    store.consume_execution(&claim).unwrap();
    assert!(native_state::AFTER_DATABASE_CLOSE.with(|hook| hook.borrow().is_none()));
    control_held(&state, false);
    drop(claim);

    let next = binding(73, RequestedMode::Permanent);
    register(&store, &next);
    let interrupted = store
        .claim_execution(&next.authorization_id, &next.plan_digest)
        .unwrap();
    let _token = reserve(&store, &interrupted, &next);
    drop(interrupted);
    control_held(&state, false);
    let recovery = store
        .claim_recovery(&next.authorization_id, &next.plan_digest)
        .unwrap();
    struct Observer(PathBuf, std::cell::Cell<bool>);
    impl RecoveryObserver for Observer {
        fn observe(&self, _: &RecoveryIntentView) -> Result<RecoveryObservation, AuditError> {
            control_held(&self.0, true);
            self.1.set(true);
            Ok(RecoveryObservation::Unknown)
        }
    }
    let observer = Observer(state.clone(), std::cell::Cell::new(false));
    assert_eq!(
        store.classify_recovery(&recovery, &observer).unwrap().len(),
        1
    );
    assert!(observer.1.get());
    drop(recovery);
    control_held(&state, false);
    StateWriteSession::open(&state, false).unwrap();
}

#[test]
fn current_global_pressure_refuses_authorization_and_plan_without_changing_old_bytes() {
    let (_temp, state, directory) = fixture();
    let store = AuditStore::open_in_state_dir(&state, AuditNamespace::General).unwrap();
    let original = fs::read(state.join("audit/audit.db")).unwrap();
    sparse(&directory, &state, 432 * 1024 * 1024);
    let authorization = binding(74, RequestedMode::Permanent);
    assert!(matches!(
        store.register_authorization(RegisterAuthorization {
            binding: authorization
        }),
        Err(AuditError::StateResourceLimit {
            resource: "state_bytes",
            ..
        })
    ));
    assert_eq!(fs::read(state.join("audit/audit.db")).unwrap(), original);
    sparse(&directory, &state, 504 * 1024 * 1024);
    assert!(matches!(
        store.save_plan_manifest(&"a".repeat(64), &serde_json::json!({"keep":true})),
        Err(AuditError::StateResourceLimit {
            resource: "state_bytes",
            ..
        })
    ));
    assert!(
        !state
            .join(format!("audit/plan-{}.json", "a".repeat(64)))
            .exists()
    );
    assert_eq!(fs::read(state.join("audit/audit.db")).unwrap(), original);
    assert_eq!(fs::read_dir(state.join("audit")).unwrap().count(), 2);
    assert_eq!(
        fs::symlink_metadata(state.join("unknown-note"))
            .unwrap()
            .len(),
        528_482_304
    );
    // Observe a byte at both ends without materializing the sparse fixture.
    let mut file = File::open(state.join("unknown-note")).unwrap();
    let mut byte = [1];
    file.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [0]);
    file.seek(SeekFrom::End(-1)).unwrap();
    file.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [0]);
    control_held(&state, false);
}

#[test]
fn plan_manifest_is_bounded_immutable_and_requires_explicit_state_admission() {
    let (_temp, state, _directory) = fixture();
    let store = AuditStore::open_in_state_dir(&state, AuditNamespace::PermanentDelete).unwrap();
    let digest = "b".repeat(64);
    let value = serde_json::json!({"canonicalDigest":digest,"plan":{"path":"quoted \" path","actions":[1,2]},"risk":"r4"});
    store.save_plan_manifest(&digest, &value).unwrap();
    let path = state.join(format!("permanent-delete-audit/plan-{digest}.json"));
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        value
    );
    assert!(
        matches!(store.save_plan_manifest(&digest, &serde_json::json!({"changed":true})), Err(AuditError::Io(ref error)) if error.kind()==std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert!(matches!(
        store.save_plan_manifest("../escape", &value),
        Err(AuditError::InvalidStableId {
            field: "plan_manifest_digest"
        })
    ));
    assert!(
        store
            .save_plan_manifest(&"c".repeat(64), &"x".repeat(9 * 1024 * 1024))
            .is_err()
    );
    assert!(
        !state
            .join(format!(
                "permanent-delete-audit/plan-{}.json",
                "c".repeat(64)
            ))
            .exists()
    );
    assert_eq!(
        fs::read_dir(state.join("permanent-delete-audit"))
            .unwrap()
            .count(),
        3
    );
    let standalone = AuditStore::open(state.parent().unwrap().join("standalone")).unwrap();
    assert!(matches!(
        standalone.save_plan_manifest(&digest, &value),
        Err(AuditError::SharedStateRequired)
    ));
}

#[test]
fn replaced_state_root_refuses_without_creating_replacement_control_or_audit_files() {
    let (_temp, state, _directory) = fixture();
    let store = AuditStore::open_in_state_dir(&state, AuditNamespace::General).unwrap();
    let original = fs::read(state.join("audit/audit.db")).unwrap();
    let retained = state.with_file_name("retained");
    fs::rename(&state, &retained).unwrap();
    let replacement = Directory::open(&state, true).unwrap();
    replacement
        .write_synced_bytes("keep", b"replacement", 11)
        .unwrap();
    assert!(matches!(
        store.save_plan_manifest(&"d".repeat(64), &0),
        Err(AuditError::StoreMismatch)
    ));
    assert!(matches!(
        store.verify_integrity(),
        Err(AuditError::StoreMismatch)
    ));
    assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
    assert_eq!(fs::read(state.join("keep")).unwrap(), b"replacement");
    assert_eq!(fs::read(retained.join("audit/audit.db")).unwrap(), original);
}

#[test]
fn replaced_control_lock_refuses_later_claimed_sql_before_touching_database() {
    let (_temp, state, directory) = fixture();
    let store = AuditStore::open_in_state_dir(&state, AuditNamespace::General).unwrap();
    let authorization = binding(75, RequestedMode::Permanent);
    register(&store, &authorization);
    let claim = store
        .claim_execution(&authorization.authorization_id, &authorization.plan_digest)
        .unwrap();
    let token = reserve(&store, &claim, &authorization);
    let original = fs::read(state.join("audit/audit.db")).unwrap();
    fs::rename(state.join(".lock"), state.join("old-control")).unwrap();
    drop(directory.create_state_file(".lock").unwrap());
    assert!(matches!(
        token.validate_current_process(),
        Err(AuditError::Io(_))
    ));
    assert!(matches!(
        store.record_outcome(&claim, &token, permanent_success()),
        Err(AuditError::Io(_))
    ));
    assert_eq!(fs::read(state.join("audit/audit.db")).unwrap(), original);
    drop(claim);
    // Restore only our controlled fixture's name, retaining the replacement file for an oracle.
    fs::rename(state.join(".lock"), state.join("replacement-control")).unwrap();
    fs::rename(state.join("old-control"), state.join(".lock")).unwrap();
    assert_eq!(
        fs::symlink_metadata(state.join("replacement-control"))
            .unwrap()
            .len(),
        0
    );
    let recovery = store
        .claim_recovery(&authorization.authorization_id, &authorization.plan_digest)
        .unwrap();
    assert_eq!(recovery.fence_epoch(), 2);
    drop(recovery);
    store.verify_integrity().unwrap();
}
