use super::*;
use std::{fs, io::Read};

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Directory) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let parent = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let parent = temp.path().to_path_buf();
    let path = parent.join("state");
    let directory = Directory::open(&path, true).unwrap();
    (temp, path, directory)
}
fn file(root: &Directory, name: &str, bytes: &[u8]) {
    root.write_synced_bytes(name, bytes, bytes.len()).unwrap();
}
fn ordinary(path: &Path) -> StateUsage {
    let mut usage = StateUsage::default();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        usage.entries += 1;
        if metadata.is_dir() {
            let child = ordinary(&entry.path());
            usage.bytes += child.bytes;
            usage.entries += child.entries;
        } else {
            assert!(metadata.is_file());
            usage.bytes += metadata.len();
        }
    }
    usage
}

#[test]
fn all_shipped_namespaces_and_unknown_files_match_ordinary_walk() {
    let (_temp, path, root) = fixture();
    file(&root, "unknown-note", b"five!");
    for name in [
        "operations",
        "audit",
        "permanent-delete-audit",
        "plans",
        "selection",
        "manifests",
        "cursors",
        "approval",
        "recovery",
        "spill",
    ] {
        file(&root.create_child(name).unwrap(), "record", b"record bytes");
    }
    let preview = root.create_child("preview-cache").unwrap();
    file(&preview, "current.json", b"pointer");
    for name in ["generations", "quarantine"] {
        file(
            &preview.create_child(name).unwrap(),
            "unknown.json",
            b"historical",
        );
    }
    let junk = root.create_child("junk-cache").unwrap();
    file(&junk, "r-fixture.json", b"facts");
    file(
        &junk.create_child("subtrees").unwrap(),
        "old.json",
        b"legacy",
    );
    let journals = root.create_child("event-journals").unwrap();
    let journal = journals.create_child(&"a".repeat(64)).unwrap();
    for name in [
        "journal.db",
        "journal.db-wal",
        "journal.db-journal",
        "journal.db-shm",
        "stream.lock",
        "unknown-record",
    ] {
        file(&journal, name, b"journal bytes");
    }
    let mut session = StateWriteSession::capture(&root).unwrap();
    let expected = ordinary(&path);
    assert_eq!(session.usage(), expected);
    session.reserve(1, 1).unwrap();
    assert_eq!(session.usage(), expected);
    let lock = junk.lock().unwrap();
    session.reserve_locked(1, 1, &junk, &lock).unwrap();
    assert_eq!(session.usage(), ordinary(&path));
}

#[test]
fn sparse_lengths_reject_growth_without_deleting_unknown_or_integrity_files() {
    let (_temp, path, root) = fixture();
    file(&root, "unknown-large", b"old");
    fs::OpenOptions::new()
        .write(true)
        .open(path.join("unknown-large"))
        .unwrap()
        .set_len(536_870_911)
        .unwrap();
    let mut session = StateWriteSession::capture(&root).unwrap();
    session.reserve(1, 0).unwrap();
    let error = session.reserve(2, 0).unwrap_err();
    let quota = resource_limit(&error).unwrap();
    assert_eq!((quota.resource, quota.limit), ("state_bytes", 536_870_912));
    assert_eq!(
        fs::metadata(path.join("unknown-large")).unwrap().len(),
        536_870_911
    );
    let mut marker = [0; 3];
    fs::File::open(path.join("unknown-large"))
        .unwrap()
        .read_exact(&mut marker)
        .unwrap();
    assert_eq!(&marker, b"old");
    assert!(!path.join("operations").exists());
}

#[test]
fn disposable_publication_preserves_terminal_record_headroom() {
    let (_temp, path, root) = fixture();
    file(&root, "protected-record", b"keep");
    fs::OpenOptions::new()
        .write(true)
        .open(path.join("protected-record"))
        .unwrap()
        .set_len(503_316_479)
        .unwrap();
    let mut session = StateWriteSession::capture(&root).unwrap();
    session.reserve_disposable(1, 1).unwrap();
    let error = session.reserve_disposable(2, 1).unwrap_err();
    assert_eq!(resource_limit(&error).unwrap().resource, "state_bytes");
    // Required records may use the preserved 32 MiB within the same 512 MiB total.
    session.reserve(33_554_433, 1).unwrap();
    assert_eq!(ordinary(&path).bytes, 503_316_479);
}

#[test]
fn unknown_nested_directory_refuses_inventory_without_touching_it() {
    let (_temp, path, root) = fixture();
    let unknown = root.create_child("personal-notes").unwrap();
    file(&unknown, "keep", b"unchanged note");
    assert!(StateWriteSession::capture(&root).is_err());
    assert_eq!(
        fs::read(path.join("personal-notes/keep")).unwrap(),
        b"unchanged note"
    );
    assert!(!path.join("operations").exists());
}

#[test]
fn retained_root_accounts_and_writes_only_original_namespace_after_rename() {
    let (_temp, path, root) = fixture();
    file(&root, "existing", b"original");
    let mut session = StateWriteSession::capture(&root).unwrap();
    let retained = path.with_file_name("retained");
    fs::rename(&path, &retained).unwrap();
    let replacement = Directory::open(&path, true).unwrap();
    file(&replacement, "existing", b"replacement");
    session.reserve(3, 1).unwrap();
    file(session.root(), "new", b"new");
    assert_eq!(session.usage().bytes, 8);
    assert_eq!(fs::read(retained.join("new")).unwrap(), b"new");
    assert_eq!(fs::read(path.join("existing")).unwrap(), b"replacement");
    assert!(!path.join("new").exists());
}

#[test]
fn bounded_global_entry_inventory_refuses_one_more_name() {
    let (_temp, path, root) = fixture();
    for index in 0..4089 {
        root.publish(&format!("empty-{index}"), |_| Ok(())).unwrap();
    }
    let mut session = StateWriteSession::capture(&root).unwrap();
    let expected = ordinary(&path);
    assert_eq!(expected.entries, 4090);
    assert_eq!(session.usage(), expected);
    session.reserve(0, 0).unwrap();
    let error = session.reserve(0, 1).unwrap_err();
    let quota = resource_limit(&error).unwrap();
    assert_eq!((quota.resource, quota.limit), ("state_entries", 4090));
    assert_eq!(ordinary(&path), expected);
}

#[test]
fn disposable_entry_admission_preserves_space_for_terminal_namespace() {
    let (_temp, path, root) = fixture();
    for index in 0..4080 {
        root.publish(&format!("empty-{index}"), |_| Ok(())).unwrap();
    }
    let mut session = StateWriteSession::capture(&root).unwrap();
    let expected = ordinary(&path);
    assert_eq!(expected.entries, 4081);
    session.reserve_disposable(0, 1).unwrap();
    let error = session.reserve_disposable(0, 2).unwrap_err();
    assert_eq!(resource_limit(&error).unwrap().resource, "state_entries");
    // A required operation can still admit its complete seven-name bootstrap.
    session.reserve(0, 7).unwrap();
    assert_eq!(ordinary(&path), expected);
}

#[cfg(unix)]
#[test]
fn linked_state_and_substituted_control_lock_refuse_admission() {
    let (_temp, path, root) = fixture();
    file(&root, "original", b"keep");
    fs::hard_link(path.join("original"), path.join("alias")).unwrap();
    assert!(StateWriteSession::capture(&root).is_err());
    assert_eq!(fs::read(path.join("original")).unwrap(), b"keep");
    fs::remove_file(path.join("alias")).unwrap();
    let mut session = StateWriteSession::capture(&root).unwrap();
    fs::rename(path.join(".lock"), path.join("retained-control")).unwrap();
    file(&root, ".lock", b"replacement");
    assert!(session.reserve(1, 1).is_err());
    assert_eq!(fs::read(path.join(".lock")).unwrap(), b"replacement");
    assert_eq!(fs::read(path.join("original")).unwrap(), b"keep");
}

#[test]
fn state_exclusion_is_nonblocking_in_an_independent_process() {
    const ROOT_ENV: &str = "SWEEPX_STATE_QUOTA_LOCK_ROOT";
    if let Some(path) = std::env::var_os(ROOT_ENV) {
        assert!(StateWriteSession::open(Path::new(&path), false).is_err());
        return;
    }
    let (_temp, path, root) = fixture();
    let session = StateWriteSession::capture(&root).unwrap();
    struct Owned(std::process::Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Owned(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "state_directory::tests::state_exclusion_is_nonblocking_in_an_independent_process",
                "--test-threads=1",
            ])
            .env(ROOT_ENV, &path)
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned quota lock oracle timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(StateWriteSession::capture(&root).is_err());
    drop(session);
    assert!(StateWriteSession::capture(&root).is_ok());
}
