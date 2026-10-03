//! Actual SQLite/C-callback tests using ordinary controlled Unix fixture storage.
//! This independently exercises descriptor I/O and locking; it is not Linux mount admission.

use super::*;
use rusqlite::OpenFlags;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn private_metadata(&self, name: Name) -> io::Result<std::fs::Metadata> {
        let metadata = std::fs::symlink_metadata(self.root.join(name.text()))?;
        // Ordinary metadata is the independent fixture oracle, not production mount logic.
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(io::Error::other("unsafe fixture entry"));
        }
        Ok(metadata)
    }
}

impl Storage for Fixture {
    fn open(&self, name: Name, create: bool, exclusive: bool) -> io::Result<File> {
        assert_ne!(
            name,
            Name::Database,
            "SQLite must use the supplied main descriptor"
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(create && !exclusive)
            .create_new(exclusive)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join(name.text()))?;
        self.private_metadata(name)?;
        Ok(file)
    }
    fn contains(&self, name: Name, file: &File) -> io::Result<bool> {
        let ordinary = self.private_metadata(name)?;
        let retained = file.metadata()?;
        Ok(ordinary.dev() == retained.dev() && ordinary.ino() == retained.ino())
    }
    fn length(&self, name: Name) -> io::Result<Option<u64>> {
        match self.private_metadata(name) {
            Ok(metadata) => Ok(Some(metadata.len())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn remove(&self, name: Name, expected: Option<&File>) -> io::Result<()> {
        self.private_metadata(name)?;
        if let Some(file) = expected
            && !self.contains(name, file)?
        {
            return Err(io::Error::other("fixture binding changed"));
        }
        std::fs::remove_file(self.root.join(name.text()))
    }
    fn sync(&self) -> io::Result<()> {
        File::open(&self.root)?.sync_all()
    }
}

fn fixture() -> (tempfile::TempDir, Arc<Fixture>, File) {
    let temp = tempfile::TempDir::new().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(root.join(Name::Database.text()))
        .unwrap();
    (temp, Arc::new(Fixture { root }), file)
}

fn connect(vfs: &Registered) -> Connection {
    Connection::open_with_flags_and_vfs(
        vfs.filename().to_str().unwrap(),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        vfs.name(),
    )
    .unwrap()
}

#[test]
fn sqlite_wal_uses_retained_descriptor_and_preserves_default_vfs() {
    let (_temp, storage, file) = fixture();
    let original = file.metadata().unwrap();
    // SAFETY: SQLite owns its process-global default pointer; no mutation here.
    let default = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
    let vfs = Registered::new(storage.clone(), file).unwrap();
    assert_eq!(unsafe { ffi::sqlite3_vfs_find(ptr::null()) }, default);
    let connection = connect(&vfs);
    assert!(vfs.owns_connection(&connection).unwrap());
    assert!(
        !vfs.owns_connection(&Connection::open_in_memory().unwrap())
            .unwrap()
    );
    assert_eq!(vfs.database().metadata().unwrap().ino(), original.ino());
    connection
        .execute_batch(
            "PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA synchronous=FULL;",
        )
        .unwrap();
    let mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
    connection.execute_batch("CREATE TABLE records(value INTEGER NOT NULL); BEGIN IMMEDIATE; INSERT INTO records VALUES(3),(8); COMMIT;").unwrap();
    assert_eq!(
        connection
            .query_row("SELECT sum(value) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        11
    );
    let ordinary: std::collections::BTreeSet<_> = std::fs::read_dir(&storage.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(ordinary.contains(&std::ffi::OsString::from("journal.db-wal")));
    assert!(!ordinary.contains(&std::ffi::OsString::from("journal.db-shm")));
    let retired_key = vfs.key;
    drop(connection);
    drop(vfs);
    assert!(registry().unwrap().lookup(retired_key).is_none());
    assert_eq!(unsafe { ffi::sqlite3_vfs_find(ptr::null()) }, default);
    // Independently read the resulting ordinary SQLite file with the default VFS.
    let ordinary = Connection::open(storage.root.join("journal.db")).unwrap();
    assert_eq!(
        ordinary
            .query_row("SELECT sum(value) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        11
    );
    assert_eq!(
        ordinary
            .pragma_query_value(None, "integrity_check", |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}

#[test]
fn ordinary_rollback_database_converts_and_remains_readable() {
    let (_temp, storage, file) = fixture();
    let ordinary = Connection::open(storage.root.join("journal.db")).unwrap();
    assert_eq!(
        ordinary
            .pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    ordinary
        .execute_batch(
            "CREATE TABLE format_oracle(value INTEGER); INSERT INTO format_oracle VALUES(21);",
        )
        .unwrap();
    drop(ordinary);
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let connection = connect(&vfs);
    // Exercise the rollback-file callbacks before the exclusive WAL transition.
    connection
        .execute_batch("INSERT INTO format_oracle VALUES(34);")
        .unwrap();
    connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL; INSERT INTO format_oracle VALUES(55);").unwrap();
    assert_eq!(
        connection
            .query_row("SELECT sum(value) FROM format_oracle", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        110
    );
    drop(connection);
    drop(vfs);
    let ordinary = Connection::open(storage.root.join("journal.db")).unwrap();
    assert_eq!(
        ordinary
            .query_row("SELECT sum(value) FROM format_oracle", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        110
    );
}

#[test]
fn callback_short_reads_zero_fill_and_growth_refusal_preserves_bytes() {
    let (_temp, storage, file) = fixture();
    file.write_at(b"abcdef", 0).unwrap();
    let vfs = Registered::new(storage.clone(), file).unwrap();
    // SAFETY: stack Slot has advertised C layout/capacity and starts unopened.
    let mut slot: Slot = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            open(
                registry().unwrap().raw(),
                vfs.filename().as_ptr(),
                &mut slot.base,
                ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_READWRITE,
                ptr::null_mut(),
            )
        },
        ffi::SQLITE_OK
    );
    let mut bytes = [0xa5_u8; 8];
    assert_eq!(
        unsafe { read(&mut slot.base, bytes.as_mut_ptr().cast(), 8, 2) },
        ffi::SQLITE_IOERR_SHORT_READ
    );
    assert_eq!(bytes, [b'c', b'd', b'e', b'f', 0, 0, 0, 0]);
    assert_eq!(
        unsafe {
            write(
                &mut slot.base,
                b"!".as_ptr().cast(),
                1,
                MAX_DATABASE_BYTES as i64,
            )
        },
        ffi::SQLITE_FULL
    );
    assert_eq!(
        unsafe { truncate(&mut slot.base, MAX_DATABASE_BYTES as i64 + 1) },
        ffi::SQLITE_FULL
    );
    assert_eq!(
        std::fs::read(storage.root.join("journal.db")).unwrap(),
        b"abcdef"
    );
    assert_eq!(unsafe { close(&mut slot.base) }, ffi::SQLITE_OK);
}

#[test]
fn replacement_refuses_reads_and_keeps_both_objects_unchanged() {
    let (_temp, storage, file) = fixture();
    file.write_at(b"original payload", 0).unwrap();
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let connection = connect(&vfs);
    assert!(vfs.owns_connection(&connection).unwrap());
    let retained = storage.root.join("retained-original");
    std::fs::rename(storage.root.join("journal.db"), &retained).unwrap();
    std::fs::write(storage.root.join("journal.db"), b"replacement bytes").unwrap();
    std::fs::set_permissions(
        storage.root.join("journal.db"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(!vfs.owns_connection(&connection).unwrap());
    let mut main: *mut ffi::sqlite3_file = ptr::null_mut();
    // SAFETY: live connection/output and our own checked method table below.
    assert_eq!(
        unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                (&mut main as *mut *mut ffi::sqlite3_file).cast(),
            )
        },
        ffi::SQLITE_OK
    );
    assert_eq!(unsafe { (*main).pMethods }, &METHODS);
    let mut buffer = [0x71_u8; 8];
    assert_eq!(
        unsafe { read(main, buffer.as_mut_ptr().cast(), 8, 0) },
        ffi::SQLITE_IOERR_READ
    );
    assert_eq!(buffer, [0x71; 8]);
    drop(connection);
    drop(vfs);
    assert_eq!(std::fs::read(retained).unwrap(), b"original payload");
    assert_eq!(
        std::fs::read(storage.root.join("journal.db")).unwrap(),
        b"replacement bytes"
    );
}

#[test]
fn unknown_temp_shm_and_exclusive_sidecar_requests_never_replace_files() {
    let (_temp, storage, file) = fixture();
    std::fs::write(
        storage.root.join("journal.db-wal"),
        b"existing auxiliary bytes",
    )
    .unwrap();
    std::fs::set_permissions(
        storage.root.join("journal.db-wal"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let raw_vfs = registry().unwrap().raw();
    let mut slot: Slot = unsafe { std::mem::zeroed() };
    let other = CString::new(format!("/{}/other.db", vfs.key)).unwrap();
    let shm = CString::new(format!("/{}/journal.db-shm", vfs.key)).unwrap();
    let wal = CString::new(format!("/{}/journal.db-wal", vfs.key)).unwrap();
    for (name, flags) in [
        (
            ptr::null(),
            ffi::SQLITE_OPEN_TEMP_DB
                | ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE
                | ffi::SQLITE_OPEN_DELETEONCLOSE,
        ),
        (
            other.as_ptr(),
            ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_READWRITE,
        ),
        (
            shm.as_ptr(),
            ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_READWRITE,
        ),
        (
            wal.as_ptr(),
            ffi::SQLITE_OPEN_WAL
                | ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE
                | ffi::SQLITE_OPEN_EXCLUSIVE,
        ),
    ] {
        assert_eq!(
            unsafe { open(raw_vfs, name, &mut slot.base, flags, ptr::null_mut()) },
            ffi::SQLITE_CANTOPEN
        );
        assert!(slot.base.pMethods.is_null());
    }
    assert_eq!(
        std::fs::read(storage.root.join("journal.db-wal")).unwrap(),
        b"existing auxiliary bytes"
    );
    let ordinary: std::collections::BTreeSet<_> = std::fs::read_dir(&storage.root)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        ordinary,
        [
            std::ffi::OsString::from("journal.db"),
            std::ffi::OsString::from("journal.db-wal")
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn sidecar_replacement_refuses_write_delete_and_reopen() {
    let (_temp, storage, file) = fixture();
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let wal = CString::new(format!("/{}/journal.db-wal", vfs.key)).unwrap();
    let raw = registry().unwrap().raw();
    // The same advertised slot/method lifecycle that SQLite uses, with real ordinary files.
    let mut slot: Slot = unsafe { std::mem::zeroed() };
    let flags = ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE;
    assert_eq!(
        unsafe { open(raw, wal.as_ptr(), &mut slot.base, flags, ptr::null_mut()) },
        ffi::SQLITE_OK
    );
    let original = b"original wal";
    assert_eq!(
        unsafe { write(&mut slot.base, original.as_ptr().cast(), 12, 0) },
        ffi::SQLITE_OK
    );
    let retained = storage.root.join("retained-wal");
    std::fs::rename(storage.root.join("journal.db-wal"), &retained).unwrap();
    std::fs::write(storage.root.join("journal.db-wal"), b"replacement wal").unwrap();
    std::fs::set_permissions(
        storage.root.join("journal.db-wal"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        unsafe { write(&mut slot.base, b"!".as_ptr().cast(), 1, 0) },
        ffi::SQLITE_IOERR_WRITE
    );
    assert_eq!(unsafe { close(&mut slot.base) }, ffi::SQLITE_OK);
    assert_eq!(
        unsafe { delete(raw, wal.as_ptr(), 0) },
        ffi::SQLITE_IOERR_DELETE
    );
    assert_eq!(
        unsafe { open(raw, wal.as_ptr(), &mut slot.base, flags, ptr::null_mut()) },
        ffi::SQLITE_CANTOPEN
    );
    assert!(slot.base.pMethods.is_null());
    assert_eq!(std::fs::read(retained).unwrap(), original);
    assert_eq!(
        std::fs::read(storage.root.join("journal.db-wal")).unwrap(),
        b"replacement wal"
    );
}

#[test]
fn retired_owner_keeps_foreign_file_memory_valid_and_refuses_io() {
    let (_temp, storage, file) = fixture();
    let vfs = Registered::new(storage.clone(), file).unwrap();
    // Model a foreign caller opening the visible driver/token before its owner does.
    let foreign = connect(&vfs);
    let key = vfs.key;
    let old_token = vfs.filename().to_owned();
    let weak = Arc::downgrade(&vfs.context);
    drop(vfs);
    assert!(registry().unwrap().lookup(key).is_none());
    assert!(
        weak.upgrade().is_some(),
        "foreign file still pins its context/quota"
    );
    let mut main: *mut ffi::sqlite3_file = ptr::null_mut();
    assert_eq!(
        unsafe {
            ffi::sqlite3_file_control(
                foreign.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                (&mut main as *mut *mut ffi::sqlite3_file).cast(),
            )
        },
        ffi::SQLITE_OK
    );
    let mut bytes = [0x67_u8; 8];
    assert_eq!(
        unsafe { read(main, bytes.as_mut_ptr().cast(), 8, 0) },
        ffi::SQLITE_IOERR_READ
    );
    assert_eq!(bytes, [0x67; 8]);
    assert!(
        Connection::open_with_flags_and_vfs(
            old_token.to_str().unwrap(),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            VFS_NAME
        )
        .is_err()
    );
    // Another lease cannot revive the old token, even for the same directory/inode.
    let new_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(storage.root.join("journal.db"))
        .unwrap();
    let fresh = Registered::new(storage.clone(), new_file).unwrap();
    assert_ne!(fresh.key, key);
    assert!(!fresh.owns_connection(&foreign).unwrap());
    drop(foreign);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        std::fs::metadata(storage.root.join("journal.db"))
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn context_quota_counts_retired_foreign_files_until_close() {
    const CHILD_ENV: &str = "SWEEPX_RETAINED_VFS_CAP_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        // Fresh process avoids other parallel tests consuming this process-wide quota.
        let mut held = Vec::new();
        for _ in 0..64 {
            let (temp, storage, file) = fixture();
            held.push((temp, Registered::new(storage, file).unwrap()));
        }
        let (_extra, storage, file) = fixture();
        assert!(Registered::new(storage.clone(), file).is_err());
        let foreign = connect(&held[0].1);
        drop(held.remove(0));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(storage.root.join("journal.db"))
            .unwrap();
        assert!(
            Registered::new(storage.clone(), file).is_err(),
            "retired foreign file still owns a quota slot"
        );
        drop(foreign);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(storage.root.join("journal.db"))
            .unwrap();
        let replacement = Registered::new(storage, file).unwrap();
        drop(replacement);
        drop(held);
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
                "retained_vfs::tests::context_quota_counts_retired_foreign_files_until_close",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "yes")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated context quota oracle failed: {status}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "isolated context quota oracle timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn legacy_shm_is_accounted_before_growth_without_opening_it() {
    let (_temp, storage, file) = fixture();
    let shm = File::create(storage.root.join("journal.db-shm")).unwrap();
    shm.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    shm.set_len(32 * 1024 * 1024).unwrap();
    drop(shm);
    let vfs = Registered::new(storage.clone(), file).unwrap();
    assert_eq!(vfs.context.growth(Name::Database, 1), Err(ffi::SQLITE_FULL));
    assert_eq!(
        std::fs::metadata(storage.root.join("journal.db"))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        std::fs::metadata(storage.root.join("journal.db-shm"))
            .unwrap()
            .len(),
        33_554_432
    );
}

#[test]
fn committed_wal_survives_abrupt_vfs_process_exit() {
    const ROOT_ENV: &str = "SWEEPX_RETAINED_VFS_CRASH_ROOT";
    if let Some(root) = std::env::var_os(ROOT_ENV) {
        let root = PathBuf::from(root);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("journal.db"))
            .unwrap();
        let vfs = Registered::new(Arc::new(Fixture { root }), file).unwrap();
        let connection = connect(&vfs);
        connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA synchronous=FULL; PRAGMA journal_mode=WAL; CREATE TABLE crash_oracle(value INTEGER); BEGIN IMMEDIATE; INSERT INTO crash_oracle VALUES(42); COMMIT;").unwrap();
        std::process::abort();
    }
    let (_temp, storage, file) = fixture();
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
                "retained_vfs::tests::committed_wal_survives_abrupt_vfs_process_exit",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROOT_ENV, &storage.root)
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned crash fixture timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        std::fs::metadata(storage.root.join("journal.db-wal"))
            .unwrap()
            .len()
            > 0
    );
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let connection = connect(&vfs);
    connection
        .execute_batch(
            "PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL;",
        )
        .unwrap();
    assert_eq!(
        connection
            .query_row("SELECT value FROM crash_oracle", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        42
    );
    drop(connection);
    drop(vfs);
    let ordinary = Connection::open(storage.root.join("journal.db")).unwrap();
    assert_eq!(
        ordinary
            .query_row("SELECT value FROM crash_oracle", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        42
    );
}

#[test]
fn rust_panic_is_contained_before_c_abi_boundary() {
    struct PanicFixture {
        storage: Arc<Fixture>,
        fail: AtomicBool,
    }
    impl Storage for PanicFixture {
        fn open(&self, name: Name, create: bool, exclusive: bool) -> io::Result<File> {
            self.storage.open(name, create, exclusive)
        }
        fn contains(&self, name: Name, file: &File) -> io::Result<bool> {
            assert!(
                !self.fail.load(Ordering::Relaxed),
                "controlled callback panic"
            );
            self.storage.contains(name, file)
        }
        fn length(&self, name: Name) -> io::Result<Option<u64>> {
            self.storage.length(name)
        }
        fn remove(&self, name: Name, expected: Option<&File>) -> io::Result<()> {
            self.storage.remove(name, expected)
        }
        fn sync(&self) -> io::Result<()> {
            self.storage.sync()
        }
    }
    let (_temp, storage, file) = fixture();
    let storage = Arc::new(PanicFixture {
        storage,
        fail: AtomicBool::new(false),
    });
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let connection = connect(&vfs);
    let mut main: *mut ffi::sqlite3_file = ptr::null_mut();
    assert_eq!(
        unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                (&mut main as *mut *mut ffi::sqlite3_file).cast(),
            )
        },
        ffi::SQLITE_OK
    );
    let methods = unsafe { &*(*main).pMethods };
    assert_eq!(methods as *const _, &METHODS);
    storage.fail.store(true, Ordering::Relaxed);
    let mut bytes = [0xa9_u8; 16];
    // Invoke the actual method installed in SQLite's C file, not just the guard helper.
    assert_eq!(
        unsafe { methods.xRead.unwrap()(main, bytes.as_mut_ptr().cast(), 16, 0) },
        ffi::SQLITE_IOERR_READ
    );
    assert_eq!(bytes, [0xa9; 16]);
    storage.fail.store(false, Ordering::Relaxed);
    drop(connection);
}

#[test]
fn sqlite_process_lock_interoperability() {
    const ROOT_ENV: &str = "SWEEPX_RETAINED_VFS_LOCK_ROOT";
    const ENGINE_ENV: &str = "SWEEPX_RETAINED_VFS_LOCK_ENGINE";
    const HELD_ENV: &str = "SWEEPX_RETAINED_VFS_LOCK_HELD";
    if let Some(root) = std::env::var_os(ROOT_ENV) {
        let root = PathBuf::from(root);
        let custom = std::env::var(ENGINE_ENV).unwrap() == "custom";
        let vfs = if custom {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join("journal.db"))
                .unwrap();
            Some(Registered::new(Arc::new(Fixture { root: root.clone() }), file).unwrap())
        } else {
            None
        };
        let connection = match &vfs {
            Some(vfs) => connect(vfs),
            None => Connection::open(root.join("journal.db")).unwrap(),
        };
        connection.busy_timeout(std::time::Duration::ZERO).unwrap();
        let result = connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL; BEGIN IMMEDIATE; ROLLBACK;");
        if std::env::var(HELD_ENV).unwrap() == "yes" {
            assert_eq!(
                result.unwrap_err().sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
        } else {
            result.unwrap();
        }
        drop(connection);
        drop(vfs);
        return;
    }
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (_temp, storage, file) = fixture();
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let connection = connect(&vfs);
    connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL; CREATE TABLE lock_oracle(value INTEGER);").unwrap();
    let observe = |engine, held| {
        let mut child = OwnedChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "retained_vfs::tests::sqlite_process_lock_interoperability",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(ROOT_ENV, &storage.root)
                .env(ENGINE_ENV, engine)
                .env(HELD_ENV, if held { "yes" } else { "no" })
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "independent SQLite lock oracle failed: {status}"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "independent SQLite lock oracle timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    observe("default", true);
    assert!(vfs.owns_connection(&connection).unwrap());
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM lock_oracle", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    observe("default", true);
    drop(connection);
    drop(vfs);
    observe("default", false);
    // Reverse direction: ordinary SQLite's exclusive lock must block this VFS too.
    let ordinary = Connection::open(storage.root.join("journal.db")).unwrap();
    ordinary
        .execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN IMMEDIATE; COMMIT;")
        .unwrap();
    observe("custom", true);
    drop(ordinary);
    observe("custom", false);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_ofd_locks_survive_other_fd_close_and_exclude_same_process_sqlite() {
    let (_temp, storage, file) = fixture();
    let vfs = Registered::new(storage.clone(), file).unwrap();
    let connection = connect(&vfs);
    connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA temp_store=MEMORY; PRAGMA journal_mode=WAL; CREATE TABLE ofd_oracle(value INTEGER);").unwrap();
    drop(File::open(storage.root.join("journal.db")).unwrap());
    let ordinary = Connection::open(storage.root.join("journal.db")).unwrap();
    ordinary.busy_timeout(std::time::Duration::ZERO).unwrap();
    assert_eq!(
        ordinary
            .execute_batch("BEGIN IMMEDIATE;")
            .unwrap_err()
            .sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy)
    );
    drop(ordinary);
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM ofd_oracle", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
