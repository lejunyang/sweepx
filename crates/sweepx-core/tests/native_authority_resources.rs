//! Public library consumers share one native authority allowance, independently of rendering.
#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use std::fs;
use sweepx_cache::native::{Directory, authority_handle_limit};
use sweepx_core::{DurableSnapshotStore, OperationSnapshot, SnapshotStore, StateError};

fn run_oracle() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let parent = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let parent = temp.path().to_path_buf();
    let state = parent.join("state");
    let directory = Directory::open(&state, true).unwrap();
    let snapshots = DurableSnapshotStore::new(&state).unwrap();
    let original = OperationSnapshot::not_found("op_native_quota", sweepx_i18n::Locale::EnUs);
    snapshots.save(&original).unwrap();
    let snapshot_path = fs::read_dir(state.join("operations"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let snapshot_bytes = fs::read(&snapshot_path).unwrap();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let audit =
        sweepx_audit::AuditStore::open_in_state_dir(&state, sweepx_audit::AuditNamespace::General)
            .unwrap();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let audit_bytes = fs::read(state.join("audit/audit.db")).unwrap();
    let mut held = Vec::new();
    for _ in 0..128 {
        match directory.child("operations") {
            Ok(copy) => held.push(copy),
            Err(error) => {
                assert_eq!(authority_handle_limit(&error), Some(128));
                break;
            }
        }
    }
    assert!(directory.child("operations").is_err());
    assert!(matches!(
        snapshots.load("op_native_quota"),
        Err(StateError::StateResourceLimit {
            resource: "native_authority_handles",
            limit: 128
        })
    ));
    let mut changed = original.clone();
    changed
        .root_paths
        .push("must not replace old snapshot".into());
    assert!(matches!(
        snapshots.save(&changed),
        Err(StateError::StateResourceLimit {
            resource: "native_authority_handles",
            limit: 128
        })
    ));
    assert!(matches!(
        DurableSnapshotStore::new(parent.join("refused-state")),
        Err(StateError::StateResourceLimit {
            resource: "native_authority_handles",
            limit: 128
        })
    ));
    assert!(!parent.join("refused-state").exists());
    // Clone owns the same root; dropping one store neither refunds nor duplicates authority.
    let survivor = snapshots.clone();
    drop(snapshots);
    assert!(directory.child("operations").is_err());
    assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_bytes);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use sweepx_audit::{AuditError, AuditNamespace, AuditStore};
        assert!(matches!(
            audit.verify_integrity(),
            Err(AuditError::StateResourceLimit {
                resource: "native_authority_handles",
                limit: 128
            })
        ));
        assert!(matches!(
            audit.save_plan_manifest(&"a".repeat(64), &0),
            Err(AuditError::StateResourceLimit {
                resource: "native_authority_handles",
                limit: 128
            })
        ));
        assert!(matches!(
            AuditStore::open_in_state_dir(&state, AuditNamespace::PermanentDelete),
            Err(AuditError::StateResourceLimit {
                resource: "native_authority_handles",
                limit: 128
            })
        ));
        assert!(!state.join("permanent-delete-audit").exists());
        assert_eq!(fs::read(state.join("audit/audit.db")).unwrap(), audit_bytes);
        let shared = audit.clone();
        drop(audit);
        assert!(directory.child("operations").is_err());
        drop(held);
        shared.verify_integrity().unwrap();
    }
    #[cfg(windows)]
    drop(held);
    assert_eq!(survivor.load("op_native_quota").unwrap().unwrap(), original);
    survivor.save(&changed).unwrap();
    assert_eq!(survivor.load("op_native_quota").unwrap().unwrap(), changed);
}

#[test]
fn cache_snapshot_and_audit_share_admission_and_preserve_records_on_refusal() {
    const CHILD_ENV: &str = "SWEEPX_CONSUMER_AUTHORITY_CAP_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        run_oracle();
        return;
    }
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cache_snapshot_and_audit_share_admission_and_preserve_records_on_refusal",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "yes")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "consumer authority oracle failed: {status}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "consumer authority oracle timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
