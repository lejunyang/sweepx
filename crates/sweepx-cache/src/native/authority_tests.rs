//! Observe the process-wide cap in a fresh exec, without reading production counters.

use super::{Directory, authority_handle_limit};
use std::io;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;

fn refused<T>(result: io::Result<T>) {
    match result {
        Ok(_) => panic!("authority request should have been refused"),
        Err(error) => {
            assert_eq!(authority_handle_limit(&error), Some(128));
            assert_eq!(error.kind(), io::ErrorKind::Other);
        }
    }
}

#[cfg(unix)]
pub(super) fn native_count(path: &Path) -> usize {
    use std::os::unix::fs::MetadataExt;
    let expected = std::fs::metadata(path).unwrap();
    #[cfg(target_os = "linux")]
    let namespace = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    let namespace = "/dev/fd";
    std::fs::read_dir(namespace)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|fd| {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // Independent kernel query of ordinary descriptor enumeration; no owner fields.
            if unsafe { libc::fstat(*fd, stat.as_mut_ptr()) } != 0 {
                return false;
            }
            let stat = unsafe { stat.assume_init() };
            #[allow(clippy::unnecessary_cast)]
            let device = stat.st_dev as u64;
            device == expected.dev() && stat.st_ino == expected.ino()
        })
        .count()
}

#[cfg(windows)]
pub(super) fn process_handles() -> usize {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut count = 0;
    // The independent Win32 query returns executive handle count, not a SweepX counter.
    assert_ne!(
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
        0
    );
    count as usize
}

fn run_oracle() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let parent = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let parent = temp.path().to_path_buf();
    let path = parent.join("private");
    let root = Arc::new(Directory::open(&path, true).unwrap());
    #[cfg(windows)]
    let baseline = process_handles();
    let mut copies = Vec::new();
    for _ in 0..127 {
        copies.push(root.retain().unwrap());
    }
    #[cfg(unix)]
    assert_eq!(native_count(&path), 128);
    #[cfg(windows)]
    assert_eq!(process_handles(), baseline + 127);
    refused(root.retain());
    refused(root.child("absent"));
    refused(root.create_child("must-not-create"));
    refused(root.lock());
    refused(Directory::open(&parent.join("must-not-create-root"), true));
    refused(sweep_state(&root));
    let cache = crate::AtomicGenerationStore::new(&path);
    assert!(matches!(
        cache.load_current(),
        Err(crate::CacheError::ResourceLimit { .. })
    ));
    assert!(matches!(
        cache.begin_write(),
        Err(crate::CacheError::ResourceLimit { .. })
    ));
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
    assert!(!parent.join("must-not-create-root").exists());

    let survivor = Arc::clone(&root);
    drop(root); // the survivor still owns the same descriptor and slot
    refused(survivor.retain());
    drop(copies.pop().unwrap());
    let lock = Arc::new(survivor.lock().unwrap());
    let lock_survivor = Arc::clone(&lock);
    drop(lock);
    refused(survivor.retain());
    #[cfg(unix)]
    {
        assert_eq!(native_count(&path), 127);
        assert_eq!(native_count(&path.join(".lock")), 1);
    }
    #[cfg(windows)]
    assert_eq!(process_handles(), baseline + 127);
    drop(lock_survivor);
    #[cfg(unix)]
    assert_eq!(native_count(&path.join(".lock")), 0);
    #[cfg(windows)]
    assert_eq!(process_handles(), baseline + 126);

    // Both a missing open and a post-open privacy failure return their slot/descriptor.
    assert_eq!(
        survivor.child("absent").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let unsafe_child = path.join("public");
    std::fs::create_dir(&unsafe_child).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unsafe_child, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(survivor.child("public").is_err());
        assert_eq!(native_count(&unsafe_child), 0);
    }
    // Windows ordinary mkdir may inherit a private DACL. A no-create missing query above is
    // its failure oracle; privacy refusal is separately covered by native DACL fixtures.
    let recovered = survivor.retain().unwrap();
    refused(survivor.retain());
    drop(recovered);
    let child = survivor.create_child("admitted").unwrap();
    refused(survivor.retain());
    drop(child);
    drop(copies);
    #[cfg(unix)]
    assert_eq!(native_count(&path), 1);
    #[cfg(windows)]
    assert_eq!(process_handles(), baseline);
    drop(survivor);
    #[cfg(unix)]
    assert_eq!(native_count(&path), 0);
    #[cfg(windows)]
    assert_eq!(process_handles(), baseline - 1);
    // Remove only our empty controlled fixture directories, not state/audit payloads.
    std::fs::remove_dir(unsafe_child).unwrap();
    std::fs::remove_dir(path.join("admitted")).unwrap();
    // All successful and failed acquisitions returned slots; real state admission works again.
    crate::state_directory::StateWriteSession::open(&path, false).unwrap();

    let root = Arc::new(Directory::open(&path, false).unwrap());
    #[cfg(windows)]
    let baseline = process_handles();
    let held = std::sync::Mutex::new(Vec::new());
    // Actual racing acquisitions remain owned until every worker has joined. An exec deadline
    // bounds a failed worker/join; do not reset or inspect the production quota counter.
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let root = Arc::clone(&root);
            let held = &held;
            scope.spawn(move || {
                for _ in 0..64 {
                    match root.retain() {
                        Ok(owner) => held.lock().unwrap().push(owner),
                        Err(error) => assert_eq!(authority_handle_limit(&error), Some(128)),
                    }
                }
            });
        }
    });
    let held = held.into_inner().unwrap();
    assert_eq!(held.len(), 127);
    #[cfg(unix)]
    assert_eq!(native_count(&path), 128);
    #[cfg(windows)]
    assert_eq!(process_handles(), baseline + 127);
    drop(held);
    #[cfg(unix)]
    assert_eq!(native_count(&path), 1);
    #[cfg(windows)]
    assert_eq!(process_handles(), baseline);
}

fn sweep_state(root: &Directory) -> io::Result<crate::state_directory::StateWriteSession> {
    crate::state_directory::StateWriteSession::capture(root)
}

#[test]
fn authority_cap_closes_before_reuse_and_refuses_creation_without_slots() {
    const CHILD_ENV: &str = "SWEEPX_NATIVE_AUTHORITY_CAP_CHILD";
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
            .args(["--exact", "native::authority_tests::authority_cap_closes_before_reuse_and_refuses_creation_without_slots", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, "yes")
            .stdin(std::process::Stdio::null())
            .spawn().unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated authority oracle failed: {status}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "authority oracle timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
