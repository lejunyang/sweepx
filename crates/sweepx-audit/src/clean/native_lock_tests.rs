//! Independent kernel observations of SQLite's database locks, without a second parent FD.

use super::*;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::time::Instant;

const PATH_ENV: &str = "SWEEPX_AUDIT_LOCK_ORACLE_PATH";
const HELD_ENV: &str = "SWEEPX_AUDIT_LOCK_ORACLE_HELD";

#[test]
fn database_lock_child() {
    let Some(path) = std::env::var_os(PATH_ENV) else {
        return;
    };
    let held = std::env::var(HELD_ENV).unwrap() == "yes";
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    // SAFETY: initialized flock requests a write-lock observation across the complete file.
    // F_GETLK never acquires a lock or changes the parent's SQLite connection state.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) },
        0
    );
    assert_eq!(lock.l_type != libc::F_UNLCK as libc::c_short, held);
}

fn observe(path: &Path, held: bool) {
    struct Owned(std::process::Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // Fresh exec is safe in the parallel Rust test harness; no fork-child Rust work or
    // output pipes, and only this owned observer can be terminated by the deadline.
    let mut child = Owned(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "clean::native_lock_tests::database_lock_child",
                "--test-threads=1",
            ])
            .env(PATH_ENV, path)
            .env(HELD_ENV, if held { "yes" } else { "no" })
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "independent audit lock observer failed: {status}"
            );
            return;
        }
        assert!(Instant::now() < deadline, "audit lock observer deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn audit_connection_returns_with_sqlite_database_lock_still_held() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap().join("audit");
    let store = AuditStore::open(root).unwrap();
    let connection = store.connection_locked().unwrap();
    observe(&store.database_path, true);
    for _ in 0..3 {
        let _guard = store.short_lock().unwrap();
        store.check_size_budget(true).unwrap();
        assert_eq!(
            store.root_native.identity().unwrap(),
            store.database_identity
        );
    }
    observe(&store.database_path, true);
    drop(connection);
    observe(&store.database_path, false);

    // Calibrate the old defect independently: default SQLite holds a lock until a foreign
    // same-process data descriptor is closed, even though the Connection remains alive.
    let ordinary = open_connection(&store.database_path).unwrap();
    observe(&store.database_path, true);
    drop(File::open(&store.database_path).unwrap());
    observe(&store.database_path, false);
    drop(ordinary);
}

#[test]
fn replaced_root_refuses_before_creating_or_touching_replacement_namespace() {
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture.path().canonicalize().unwrap();
    let root = base.join("audit");
    let store = AuditStore::open(&root).unwrap();
    let original = fs::read(root.join(DATABASE_FILE)).unwrap();
    let retained = base.join("retained");
    fs::rename(&root, &retained).unwrap();
    let replacement = sweepx_cache::native::Directory::open(&root, true).unwrap();
    replacement
        .write_synced_bytes("keep", b"replacement", 11)
        .unwrap();
    assert!(matches!(
        store.verify_integrity(),
        Err(AuditError::StoreMismatch)
    ));
    assert!(matches!(
        store.connection_locked(),
        Err(AuditError::StoreMismatch)
    ));
    assert!(matches!(
        store.check_size_budget(true),
        Err(AuditError::StoreMismatch)
    ));
    assert!(!root.join(LOCK_FILE).exists());
    assert!(!root.join(DATABASE_FILE).exists());
    assert_eq!(fs::read(root.join("keep")).unwrap(), b"replacement");
    assert_eq!(fs::read(retained.join(DATABASE_FILE)).unwrap(), original);
}

#[test]
fn dangling_rollback_link_refuses_without_opening_sqlite_or_changing_old_bytes() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap().join("audit");
    let store = AuditStore::open(&root).unwrap();
    let original = fs::read(root.join(DATABASE_FILE)).unwrap();
    let target = root.with_file_name("missing-personal-file");
    std::os::unix::fs::symlink(&target, root.join("audit.db-journal")).unwrap();
    assert!(matches!(
        store.verify_integrity(),
        Err(AuditError::SymlinkRejected(_))
    ));
    assert!(matches!(
        store.connection_locked(),
        Err(AuditError::SymlinkRejected(_))
    ));
    assert_eq!(
        fs::read_link(root.join("audit.db-journal")).unwrap(),
        target
    );
    assert_eq!(fs::read(root.join(DATABASE_FILE)).unwrap(), original);
}

#[test]
fn rollback_bytes_participate_in_preclaim_budget_without_eviction() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap().join("audit");
    let store = AuditStore::open(&root).unwrap();
    let original = fs::read(root.join(DATABASE_FILE)).unwrap();
    let native = sweepx_cache::native::Directory::open(&root, false).unwrap();
    native
        .write_synced_bytes("audit.db-journal", b"keep", 4)
        .unwrap();
    let rollback = root.join("audit.db-journal");
    OpenOptions::new()
        .write(true)
        .open(&rollback)
        .unwrap()
        .set_len(84_934_656)
        .unwrap();
    assert_eq!(fs::symlink_metadata(&rollback).unwrap().len(), 84_934_656);
    assert!(matches!(
        AuditStore::open(&root),
        Err(AuditError::DatabaseTooLarge)
    ));
    assert!(matches!(
        store.connection_locked(),
        Err(AuditError::DatabaseTooLarge)
    ));
    assert!(matches!(
        store.claim_execution(
            &AuthorizationId::new("missing-budget-binding").unwrap(),
            &DigestString::new("missing-budget-digest").unwrap()
        ),
        Err(AuditError::DatabaseTooLarge)
    ));
    assert_eq!(fs::symlink_metadata(rollback).unwrap().len(), 84_934_656);
    assert_eq!(fs::read(root.join(DATABASE_FILE)).unwrap(), original);
}
