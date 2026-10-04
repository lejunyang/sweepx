//! Public storage and scanner consumers share native admission, independently of rendering.
#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use std::fs;
use sweepx_cache::native::{Directory, NativeFile, handle_limit};
use sweepx_core::{DurableSnapshotStore, OperationSnapshot, SnapshotStore, StateError};

fn run_oracle(io_quota: bool) {
    let expected_resource = if io_quota {
        "native_io_handles"
    } else {
        "native_authority_handles"
    };
    let expected_limit = if io_quota { 256 } else { 128 };
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
    let mut files = Vec::new();
    if io_quota {
        let seed = NativeFile::admit(fs::File::open(&snapshot_path).unwrap()).unwrap();
        loop {
            match seed.try_clone() {
                Ok(file) => files.push(file),
                Err(error) => {
                    let refusal = handle_limit(&error).unwrap();
                    assert_eq!(refusal.resource, expected_resource);
                    assert_eq!(refusal.limit as u64, expected_limit);
                    break;
                }
            }
        }
        files.push(seed);
    } else {
        for _ in 0..128 {
            match directory.child("operations") {
                Ok(copy) => held.push(copy),
                Err(error) => {
                    assert_eq!(handle_limit(&error).unwrap().resource, expected_resource);
                    break;
                }
            }
        }
    }
    assert!(directory.child("operations").is_err());
    assert!(matches!(
        snapshots.load("op_native_quota"),
        Err(StateError::StateResourceLimit {
            resource, limit
        }) if resource == expected_resource && limit == expected_limit
    ));
    let mut changed = original.clone();
    changed
        .root_paths
        .push("must not replace old snapshot".into());
    assert!(matches!(
        snapshots.save(&changed),
        Err(StateError::StateResourceLimit {
            resource, limit
        }) if resource == expected_resource && limit == expected_limit
    ));
    assert!(matches!(
        DurableSnapshotStore::new(parent.join("refused-state")),
        Err(StateError::StateResourceLimit {
            resource, limit
        }) if resource == expected_resource && limit == expected_limit
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
                resource, limit
            }) if resource == expected_resource && limit == expected_limit
        ));
        assert!(matches!(
            audit.save_plan_manifest(&"a".repeat(64), &0),
            Err(AuditError::StateResourceLimit {
                resource, limit
            }) if resource == expected_resource && limit == expected_limit
        ));
        assert!(matches!(
            AuditStore::open_in_state_dir(&state, AuditNamespace::PermanentDelete),
            Err(AuditError::StateResourceLimit {
                resource, limit
            }) if resource == expected_resource && limit == expected_limit
        ));
        assert!(!state.join("permanent-delete-audit").exists());
        assert_eq!(fs::read(state.join("audit/audit.db")).unwrap(), audit_bytes);
        let shared = audit.clone();
        drop(audit);
        assert!(directory.child("operations").is_err());
        drop(held);
        drop(files);
        shared.verify_integrity().unwrap();
    }
    #[cfg(windows)]
    {
        drop(held);
        drop(files);
    }
    assert_eq!(survivor.load("op_native_quota").unwrap().unwrap(), original);
    survivor.save(&changed).unwrap();
    assert_eq!(survivor.load("op_native_quota").unwrap().unwrap(), changed);
}

#[test]
fn cache_snapshot_and_audit_share_admission_and_preserve_records_on_refusal() {
    const CHILD_ENV: &str = "SWEEPX_CONSUMER_AUTHORITY_CAP_CHILD";
    if let Some(mode) = std::env::var_os(CHILD_ENV) {
        run_oracle(mode == "io");
        return;
    }
    for mode in ["authority", "io"] {
        run_child_oracle(
            "cache_snapshot_and_audit_share_admission_and_preserve_records_on_refusal",
            CHILD_ENV,
            mode,
        );
    }
}

fn run_child_oracle(name: &str, environment: &str, mode: &str) {
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(environment, mode)
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "{name} ({mode}) failed: {status}");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{name} ({mode}) timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn run_scan_oracle() {
    use std::collections::BTreeSet;
    use sweepx_platform::{
        BoundedRegularFileReadError, BoundedRegularFileReadRequest, CancellationToken,
        DirectoryReadLimits, PlatformError, PlatformScanner, ScanRoot,
    };
    use sweepx_scanner::HostPlatformScanner;

    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let parent = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let parent = temp.path().to_path_buf();
    let root = parent.join("scan");
    let state = parent.join("state");
    fs::create_dir_all(root.join("child")).unwrap();
    let payload = root.join("payload");
    fs::write(&payload, b"kept bytes").unwrap();
    let expected = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<BTreeSet<_>>();
    // Native fixtures are counted independently of the production counters and marker limit.
    #[cfg(unix)]
    let identities = {
        use std::os::unix::fs::MetadataExt;
        fs::create_dir(&state).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        [&root, &state, &payload]
            .into_iter()
            .map(|path| {
                let stat = fs::metadata(path).unwrap();
                (stat.dev(), stat.ino())
            })
            .collect::<BTreeSet<_>>()
    };
    #[cfg(unix)]
    let observed_handles = || {
        use std::os::unix::fs::MetadataExt;
        #[cfg(target_os = "linux")]
        let namespace = "/proc/self/fd";
        #[cfg(target_os = "macos")]
        let namespace = "/dev/fd";
        // Do not count aliases opened by this oracle: snapshot the names before fstat aliases.
        let names = fs::read_dir(namespace)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        names
            .into_iter()
            .filter_map(|path| fs::File::open(path).ok()?.metadata().ok())
            .filter(|meta| identities.contains(&(meta.dev(), meta.ino())))
            .count()
    };
    #[cfg(windows)]
    let observed_handles = || {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        let mut count = 0;
        // Independent executive handle oracle; this does not read our production pool.
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
            0
        );
        usize::try_from(count).unwrap()
    };
    let baseline = observed_handles();
    let directory = Directory::open(&state, true).unwrap();
    let platform = HostPlatformScanner::new();
    let scan_root = ScanRoot::new(root.clone()).unwrap();
    let cancel = CancellationToken::new();
    let mut roots = (0..16)
        .map(|_| platform.admit_root(&scan_root, &cancel).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(observed_handles() - baseline, 17);
    let first_batch = platform
        .enumerate_children(
            &mut roots[0].directory,
            &cancel,
            DirectoryReadLimits {
                max_batch_entries: 16,
                max_batch_bytes: 16 * 1024,
            },
        )
        .unwrap();
    #[cfg(target_os = "linux")]
    assert_eq!(observed_handles() - baseline, 18); // retained root plus its separate DIR stream
    #[cfg(not(target_os = "linux"))]
    assert_eq!(observed_handles() - baseline, 17);

    let seed = NativeFile::admit(fs::File::open(&payload).unwrap()).unwrap();
    let mut files = Vec::new();
    loop {
        match seed.try_clone() {
            Ok(file) => files.push(file),
            Err(error) => {
                let marker = handle_limit(&error).unwrap();
                assert_eq!(marker.resource, "native_io_handles");
                assert_eq!(marker.limit, 256);
                break;
            }
        }
    }
    assert_eq!(observed_handles() - baseline, 256);
    assert!(matches!(
        platform.admit_root(&scan_root, &cancel),
        Err(PlatformError::ResourceLimit(_))
    ));
    let refused = sweepx_scanner::Scanner::new(
        HostPlatformScanner::new(),
        sweepx_scanner::ScannerOptions::default(),
    )
    .scan(std::slice::from_ref(&scan_root), &cancel);
    assert!(matches!(
        refused,
        Err(sweepx_scanner::ScanError::Platform(
            PlatformError::ResourceLimit(_)
        ))
    ));
    let token = first_batch
        .entries
        .iter()
        .find(|entry| entry.path == payload)
        .unwrap();
    let inspected = sweepx_platform::inspect_bound_child_with_mount_identity(
        &platform,
        &roots[0].directory,
        &root,
        token,
        &cancel,
    );
    assert!(matches!(
        inspected,
        Err(PlatformError::ResourceLimit(_))
            | Ok(sweepx_platform::WalkEntry::Error(
                sweepx_platform::ErrorRecord {
                    kind: sweepx_platform::ErrorKind::ResourceLimit,
                    reason: sweepx_model::ReasonCode::ResourceLimit,
                    ..
                }
            ))
    ));
    assert!(
        matches!(directory.child("must-not-create"), Err(error) if handle_limit(&error).is_some())
    );
    assert!(!state.join("must-not-create").exists());
    #[cfg(unix)]
    let name = sweepx_model::NativeName::unix(b"payload".to_vec());
    #[cfg(windows)]
    let name =
        sweepx_model::NativeName::windows_utf16("payload".encode_utf16().collect::<Vec<_>>());
    let request = BoundedRegularFileReadRequest::establish_live(name, 32).unwrap();
    let refusal = platform
        .read_regular_file_relative(&roots[0].directory, &request, &cancel)
        .unwrap_err();
    assert!(!refusal.is_verified_absent());
    assert!(
        matches!(refusal, BoundedRegularFileReadError::ResourceLimit(limit)
        if limit.resource == "native_io_handles" && limit.limit == 256)
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        platform.admit_root(&scan_root, &cancelled),
        Err(PlatformError::Cancelled)
    ));
    assert_eq!(observed_handles() - baseline, 256);
    assert_eq!(fs::read(&payload).unwrap(), b"kept bytes");

    // One released data owner permits one Linux cursor. Other backends enumerate on their
    // already retained owner; neither invents a second reservation or opens a sibling queue.
    drop(files.pop().unwrap());
    let mut names = BTreeSet::new();
    loop {
        let batch = platform
            .enumerate_children(
                &mut roots[1].directory,
                &cancel,
                DirectoryReadLimits {
                    max_batch_entries: 16,
                    max_batch_bytes: 16 * 1024,
                },
            )
            .unwrap();
        names.extend(batch.entries.into_iter().map(|entry| entry.path));
        if batch.end_of_directory {
            break;
        }
    }
    assert_eq!(names, expected);
    #[cfg(target_os = "linux")]
    assert_eq!(observed_handles() - baseline, 256);
    #[cfg(not(target_os = "linux"))]
    assert_eq!(observed_handles() - baseline, 255);

    drop(files);
    drop(seed);
    let observed = platform
        .read_regular_file_relative(&roots[0].directory, &request, &cancel)
        .unwrap();
    assert_eq!(observed.bytes, b"kept bytes");
    let before = observed_handles();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let stream = sweepx_platform::RegularFileStreamRequest::new(
            request.child_name().clone(),
            sweepx_platform::RegularFileReadExpectation::EstablishLive,
            0,
            32,
            None,
        )
        .unwrap();
        platform.stream_regular_file_relative(&roots[0].directory, &stream, &cancel, &mut |_| {
            panic!("controlled content callback panic")
        })
    }));
    let panic = panic.expect_err("the native content callback must be reached");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"controlled content callback panic")
    );
    assert_eq!(observed_handles(), before);
    drop(roots);
    drop(directory);
    assert_eq!(observed_handles(), baseline);
}

#[test]
fn scanner_and_storage_share_actual_io_lifetimes() {
    const CHILD_ENV: &str = "SWEEPX_SCAN_IO_CAP_CHILD";
    if std::env::var_os(CHILD_ENV).is_some() {
        run_scan_oracle();
        return;
    }
    run_child_oracle(
        "scanner_and_storage_share_actual_io_lifetimes",
        CHILD_ENV,
        "scan",
    );
}
