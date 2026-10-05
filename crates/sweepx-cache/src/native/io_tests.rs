//! Real descriptor oracles in an isolated exec; no production quota inspection/reset.

use super::{Directory, HandleLimit, NativeFile, handle_limit};
use std::io;
use std::sync::Arc;

fn refused<T>(result: io::Result<T>) {
    let Err(error) = result else {
        panic!("I/O request should have been refused")
    };
    assert_eq!(
        handle_limit(&error),
        Some(HandleLimit {
            resource: "native_io_handles",
            limit: 256
        })
    );
}

fn run_oracle() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let parent = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let parent = temp.path().to_path_buf();
    let path = parent.join("private");
    let root = Arc::new(Directory::open(&path, true).unwrap());
    root.write_json("seed.json", &42, 32).unwrap();
    let original = std::fs::read(path.join("seed.json")).unwrap();
    let seed = Arc::new(root.open_file("seed.json").unwrap());
    #[cfg(windows)]
    let baseline = super::authority_tests::process_handles();
    let mut held = (0..254)
        .map(|_| seed.try_clone().unwrap())
        .collect::<Vec<_>>();
    #[cfg(unix)]
    {
        assert_eq!(super::authority_tests::native_count(&path), 1);
        assert_eq!(
            super::authority_tests::native_count(&path.join("seed.json")),
            255
        );
    }
    #[cfg(windows)]
    assert_eq!(super::authority_tests::process_handles(), baseline + 254);
    refused(seed.try_clone());
    refused(NativeFile::admit(
        std::fs::File::open(path.join("seed.json")).unwrap(),
    ));
    refused(root.create_child("must-not-create"));
    refused(root.lock());
    refused(root.create_state_file("must-not-create.db"));
    refused(root.entries(|_| panic!("refused enumeration must not visit")));
    refused(root.write_json("seed.json", &99, 32));
    refused(root.write_json("must-not-create.json", &0, 32));
    refused(Directory::open(&parent.join("must-not-create-root"), true));
    #[cfg(unix)]
    {
        refused(root.directory_file());
    }
    let cache = crate::AtomicGenerationStore::new(&path);
    assert!(matches!(
        cache.begin_write(),
        Err(crate::CacheError::ResourceLimit { .. })
    ));
    assert_eq!(std::fs::read(path.join("seed.json")).unwrap(), original);
    assert!(!parent.join("must-not-create-root").exists());
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
    let survivor = Arc::clone(&seed);
    drop(seed);
    refused(survivor.try_clone());
    drop(held.pop().unwrap());

    // Exactly one slot remains. The independent enumeration cursor must own it until return.
    let mut visited = 0;
    let error = root
        .entries(|name| {
            assert_eq!(name, "seed.json");
            visited += 1;
            refused(survivor.try_clone());
            #[cfg(unix)]
            assert_eq!(super::authority_tests::native_count(&path), 2);
            Err(io::Error::other("controlled callback refusal"))
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "controlled callback refusal");
    assert_eq!(visited, 1);
    let recovered = survivor.try_clone().unwrap();
    drop(recovered);
    assert!(
        std::panic::catch_unwind(|| root.entries(|_| panic!("controlled visitor unwind"))).is_err()
    );
    drop(survivor.try_clone().unwrap());
    let error = root
        .publish("new.json", |_file| {
            refused(survivor.try_clone());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(_file.metadata()?.nlink(), 1);
            }
            Err(io::Error::other("controlled encoder refusal"))
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "controlled encoder refusal");
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
    drop(survivor.try_clone().unwrap());
    drop(held);
    #[cfg(unix)]
    assert_eq!(
        super::authority_tests::native_count(&path.join("seed.json")),
        1
    );
    #[cfg(windows)]
    assert_eq!(super::authority_tests::process_handles(), baseline);

    let held = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let file = Arc::clone(&survivor);
            let held = &held;
            scope.spawn(move || {
                for _ in 0..64 {
                    match file.try_clone() {
                        Ok(file) => held.lock().unwrap().push(file),
                        Err(error) => {
                            assert_eq!(handle_limit(&error).unwrap().resource, "native_io_handles")
                        }
                    }
                }
            });
        }
    });
    let held = held.into_inner().unwrap();
    assert_eq!(held.len(), 254);
    #[cfg(unix)]
    assert_eq!(
        super::authority_tests::native_count(&path.join("seed.json")),
        255
    );
    #[cfg(windows)]
    assert_eq!(super::authority_tests::process_handles(), baseline + 254);
    drop(held);
    drop(survivor);
    #[cfg(unix)]
    assert_eq!(
        super::authority_tests::native_count(&path.join("seed.json")),
        0
    );
    #[cfg(windows)]
    assert_eq!(super::authority_tests::process_handles(), baseline - 1);
    root.write_json("seed.json", &99, 32).unwrap();
    assert_eq!(std::fs::read(path.join("seed.json")).unwrap(), b"99");
}

#[test]
fn io_cap_follows_files_enumeration_and_encoder_until_actual_close() {
    const CHILD_ENV: &str = "SWEEPX_NATIVE_IO_CAP_CHILD";
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
                "native::io_tests::io_cap_follows_files_enumeration_and_encoder_until_actual_close",
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
            assert!(status.success(), "I/O oracle failed: {status}");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "I/O oracle timed out");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
