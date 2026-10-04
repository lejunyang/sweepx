//! Independent kernel observations of SQLite's database locks, without a second parent FD.

use super::*;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
fn audit_sql_interval_keeps_ofd_locks_through_checks_and_foreign_fd_close() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap().join("audit");
    let store = AuditStore::open(root).unwrap();
    store
        .with_connection_locked(|_| {
            observe(&store.database_path, true);
            for _ in 0..3 {
                let _guard = store.short_lock().unwrap();
                store.check_size_budget(true).unwrap();
                assert_eq!(
                    store.root_native.identity().unwrap(),
                    store.database_identity
                );
            }
            drop(File::open(&store.database_path).unwrap());
            observe(&store.database_path, true);
            Ok(())
        })
        .unwrap();
    observe(&store.database_path, false);

    // Calibrate the old defect independently: default SQLite holds a lock until a foreign
    // same-process data descriptor is closed, even though the Connection remains alive.
    let ordinary = Connection::open(&store.database_path).unwrap();
    ordinary
        .execute_batch("PRAGMA journal_mode=WAL; BEGIN; SELECT database_id FROM store_meta;")
        .unwrap();
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
        store.with_connection_locked(|_| Ok(())),
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn database_replaced_after_admission_refuses_before_sql_or_sidecar_creation() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap().join("audit");
    let store = AuditStore::open(&root).unwrap();
    let original = fs::read(root.join(DATABASE_FILE)).unwrap();
    let swapped_root = root.clone();
    native_state::BEFORE_DATABASE_OPEN.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            fs::rename(
                swapped_root.join(DATABASE_FILE),
                swapped_root.join("original.db"),
            )
            .unwrap();
            sweepx_cache::native::Directory::open(&swapped_root, false)
                .unwrap()
                .write_synced_bytes(DATABASE_FILE, b"keep", 4)
                .unwrap();
        }));
    });
    assert!(matches!(
        store.with_connection_locked::<()>(|_| panic!("replacement must be refused before SQL")),
        Err(AuditError::StoreMismatch)
    ));
    assert!(native_state::BEFORE_DATABASE_OPEN.with(|hook| hook.borrow().is_none()));
    assert_eq!(fs::read(root.join(DATABASE_FILE)).unwrap(), b"keep");
    assert_eq!(fs::read(root.join("original.db")).unwrap(), original);
    for name in ["audit.db-wal", "audit.db-shm", "audit.db-journal"] {
        assert!(!root.join(name).exists(), "unexpected sidecar: {name}");
    }
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
        store.with_connection_locked(|_| Ok(())),
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
        store.with_connection_locked(|_| Ok(())),
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

#[cfg(target_os = "macos")]
#[test]
fn native_policy_covers_real_sql_callbacks_and_close_then_restores() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap().join("audit");
    let store = AuditStore::open(&root).unwrap();
    let previous = native_state::current_policy();
    native_state::POLICY_PROBE.with(|p| p.set(Some((0, false))));
    store.with_connection_locked(|connection| {
        assert_eq!(native_state::current_policy(), 1);
        connection.execute_batch("BEGIN IMMEDIATE; UPDATE store_meta SET next_fence_epoch=next_fence_epoch+1; UPDATE store_meta SET next_fence_epoch=next_fence_epoch-1; COMMIT;")?;
        Ok(())
    }).unwrap();
    let (seen, failed) = native_state::POLICY_PROBE.with(|p| p.replace(None).unwrap());
    assert!(!failed, "unprotected native phase bitmap: {seen}");
    assert_eq!(
        seen, 255,
        "open/binding/accounting/sync/remove/SQL/close all observed"
    );
    assert_eq!(native_state::current_policy(), previous);
    store.verify_integrity().unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn actual_audit_write_callback_refuses_growth_and_preserves_database_bytes() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap().join("audit");
    let store = AuditStore::open(&root).unwrap();
    let original = fs::read(root.join(DATABASE_FILE)).unwrap();
    store
        .with_connection_locked(|connection| {
            use rusqlite::ffi;
            let mut file: *mut ffi::sqlite3_file = std::ptr::null_mut();
            // Public C file-control returns the actual installed object, not a display filename.
            assert_eq!(
                unsafe {
                    ffi::sqlite3_file_control(
                        connection.handle(),
                        c"main".as_ptr(),
                        ffi::SQLITE_FCNTL_FILE_POINTER,
                        (&mut file as *mut *mut ffi::sqlite3_file).cast(),
                    )
                },
                ffi::SQLITE_OK
            );
            assert!(!file.is_null());
            let methods = unsafe { &*(*file).pMethods };
            assert_eq!(methods.iVersion, 2);
            assert!(methods.xFetch.is_none());
            assert_eq!(
                unsafe { methods.xWrite.unwrap()(file, b"keep".as_ptr().cast(), 4, 67_108_864) },
                ffi::SQLITE_FULL
            );
            assert_eq!(fs::read(root.join(DATABASE_FILE)).unwrap(), original);
            Ok(())
        })
        .unwrap();
    assert_eq!(fs::read(root.join(DATABASE_FILE)).unwrap(), original);
    store.verify_integrity().unwrap();
}
