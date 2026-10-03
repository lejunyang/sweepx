//! Linux runtime checks: independent fdinfo oracle and isolated, opt-in bind mounts.

use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn fixture() -> (tempfile::TempDir, PathBuf, Directory) {
    let guard = tempfile::tempdir().unwrap();
    let path = guard.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory::open(&path, false).unwrap();
    (guard, path, directory)
}

fn fdinfo_mount(fd: i32) -> u64 {
    // Independent kernel interface, with bounded diagnostic input; not a second statx call.
    let mut bytes = Vec::new();
    File::open(format!("/proc/self/fdinfo/{fd}"))
        .unwrap()
        .take(8193)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 8192);
    std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:").map(str::trim))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn descriptor_mounts_and_accounting_match_independent_kernel_and_file_oracles() {
    let (_guard, path, directory) = fixture();
    directory
        .mount
        .require_same(
            mount::Identity::observe(0x1000, fdinfo_mount(directory.fd.as_raw_fd())).unwrap(),
        )
        .unwrap();
    let child = directory.create_child("child").unwrap();
    assert!(directory.same_child("child", &child).unwrap());
    child.write_json("record", &"native bytes", 128).unwrap();
    let file = File::open(path.join("child/record")).unwrap();
    child
        .mount
        .require_same(mount::Identity::observe(0x1000, fdinfo_mount(file.as_raw_fd())).unwrap())
        .unwrap();
    let ordinary = file.metadata().unwrap();
    let accounted = child.accounting_metadata("record").unwrap();
    assert_eq!(accounted.bytes, 14);
    assert_eq!(accounted.bytes, ordinary.len());
    assert_eq!(
        accounted.identity,
        [ordinary.dev(), ordinary.ino(), ordinary.nlink()]
    );
    assert_eq!(accounted.changed, (ordinary.ctime(), ordinary.ctime_nsec()));
    let lock = directory.lock().unwrap();
    assert_eq!(
        fdinfo_mount(lock.file.as_raw_fd()),
        fdinfo_mount(directory.fd.as_raw_fd())
    );
    let retained = directory.retain().unwrap();
    directory.mount.require_same(retained.mount).unwrap();
}

#[test]
fn mismatched_retained_mount_refuses_work_and_preserves_pointer_bytes() {
    let (_guard, path, mut directory) = fixture();
    directory
        .write_json("current.json", &"old pointer", 128)
        .unwrap();
    directory.create_child("child").unwrap();
    let before = std::fs::read(path.join("current.json")).unwrap();
    let actual = fdinfo_mount(directory.fd.as_raw_fd());
    directory.mount = mount::Identity::observe(0x1000, actual.wrapping_add(1)).unwrap();
    assert!(directory.retain().is_err());
    assert!(directory.child("child").is_err());
    assert!(directory.create_child("new").is_err());
    assert!(directory.lock().is_err());
    assert!(directory.accounting_metadata("current.json").is_err());
    assert!(directory.metadata("current.json").is_err());
    assert!(directory.read_bytes("current.json", 128).is_err());
    assert!(
        ReadBudget::new(Limits::default())
            .read::<String>(&directory, "current.json", Limits::default(), |_| 0)
            .is_none()
    );
    assert!(
        directory
            .entries_all(|_| panic!("invalid authority must not enumerate"))
            .is_err()
    );
    assert!(
        directory
            .publish("current.json", |_| panic!("must not encode"))
            .is_err()
    );
    assert!(directory.remove("current.json").is_err());
    assert_eq!(std::fs::read(path.join("current.json")).unwrap(), before);
    assert!(!path.join("new").exists());
    assert_eq!(std::fs::read_dir(path).unwrap().count(), 2);
}

const BIND_TEST: &str =
    "native::unix::linux_tests::same_device_bind_mounts_are_refused_in_private_namespace";
const PARENT_NAMESPACE: &str = "SWEEPX_TEST_BIND_PARENT_MOUNT_NAMESPACE";

#[test]
#[ignore = "requires Linux unshare user/mount namespaces; run this exact test with --ignored"]
fn same_device_bind_mounts_are_refused_in_private_namespace() {
    let Some(parent_namespace) = std::env::var_os(PARENT_NAMESPACE) else {
        // Only our child creates mounts; its mount namespace must differ from this process.
        // No global environment or host mount table changes, and no reader pipes to deadlock.
        let parent = std::fs::metadata("/proc/self/ns/mnt").unwrap().ino();
        let child = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", BIND_TEST, "--ignored", "--nocapture", "--test-threads=1"])
            .env(PARENT_NAMESPACE, parent.to_string())
            .spawn()
            .expect("Linux util-linux unshare is required; lack of namespace support is a qualification gap");
        struct Child(std::process::Child, bool);
        impl Drop for Child {
            fn drop(&mut self) {
                if !self.1 {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        let mut child = Child(child, false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                child.1 = true;
                assert!(
                    status.success(),
                    "private-namespace bind fixture failed: {status}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "namespace fixture exceeded 30 seconds"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    let parent: u64 = parent_namespace.to_str().unwrap().parse().unwrap();
    assert_ne!(
        std::fs::metadata("/proc/self/ns/mnt").unwrap().ino(),
        parent,
        "refuse mounts in the parent namespace"
    );
    // Even an accidentally inherited test marker must not admit the initial user namespace.
    // A one-ID map is the controlled --map-root-user namespace, never the host's full map.
    let mut uid_map = String::new();
    File::open("/proc/self/uid_map")
        .unwrap()
        .take(1025)
        .read_to_string(&mut uid_map)
        .unwrap();
    assert!(uid_map.len() <= 1024);
    let mapping: Vec<_> = uid_map.split_whitespace().collect();
    assert_eq!(mapping.len(), 3);
    assert_eq!(mapping[0], "0");
    assert_eq!(
        mapping[2], "1",
        "refuse mounts in an uncontrolled user namespace"
    );
    // SAFETY: only the proven private mount namespace is changed; no host propagation.
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0,
        "isolate propagation: {}",
        io::Error::last_os_error()
    );

    struct Bound(CString);
    impl Drop for Bound {
        fn drop(&mut self) {
            // SAFETY: only a fixture mount in our private namespace; lazy detach also works
            // on panic with retained cache descriptors. Parent namespace is never modified.
            unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
        }
    }
    fn bind(source: &Path, target: &Path) -> Bound {
        let source = CString::new(source.as_os_str().as_encoded_bytes()).unwrap();
        let target = CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0,
            "bind fixture: {}",
            io::Error::last_os_error()
        );
        Bound(target)
    }

    let (_guard, path, directory) = fixture();
    directory
        .write_json("current.json", &"old pointer", 128)
        .unwrap();
    directory.write_json("record", &"payload", 128).unwrap();
    let before = std::fs::read(path.join("current.json")).unwrap();
    let record = path.join("record");
    let original = std::fs::metadata(&record).unwrap();
    let _bound_record = bind(&record, &record);
    let bound = std::fs::metadata(&record).unwrap();
    assert_eq!(
        (original.dev(), original.ino(), original.nlink()),
        (bound.dev(), bound.ino(), bound.nlink())
    );
    assert!(directory.accounting_metadata("record").is_err());
    assert!(directory.metadata("record").is_err());
    assert!(directory.read_bytes("record", 128).is_err());
    assert!(
        ReadBudget::new(Limits::default())
            .read::<String>(&directory, "record", Limits::default(), |_| 0)
            .is_none()
    );
    assert!(
        directory
            .publish("record", |_| panic!(
                "refuse mounted destination before encoder"
            ))
            .is_err()
    );
    assert!(directory.remove("record").is_err());
    assert_eq!(std::fs::read(&record).unwrap(), b"\"payload\"");

    let child = directory.create_child("child").unwrap();
    let original = child.private().unwrap();
    let child_path = path.join("child");
    let _bound_child = bind(&child_path, &child_path);
    let bound = std::fs::metadata(&child_path).unwrap();
    assert_eq!((original.dev(), original.ino()), (bound.dev(), bound.ino()));
    assert!(directory.child("child").is_err());
    assert!(directory.create_child("child").is_err());
    assert!(directory.same_child("child", &child).is_err());
    // An explicitly chosen root can itself be a mount. Its descendants stay in that scope.
    Directory::open(&child_path, false)
        .unwrap()
        .write_json("fact", &"own mount", 128)
        .unwrap();

    let lock = directory.lock().unwrap();
    drop(lock);
    let _bound_lock = bind(&path.join(".lock"), &path.join(".lock"));
    assert!(directory.lock().is_err());

    let mut temporary = None;
    let error = directory
        .publish("current.json", |file| {
            file.write_all(b"new pointer bytes")?;
            let path = std::fs::read_dir(&path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .as_encoded_bytes()
                        .starts_with(b".sweepx-")
                })
                .unwrap();
            temporary = Some(bind(&path, &path));
            Ok(())
        })
        .unwrap_err();
    assert!(error.to_string().contains("mount boundary"));
    assert_eq!(std::fs::read(path.join("current.json")).unwrap(), before);
    drop(temporary);
}
