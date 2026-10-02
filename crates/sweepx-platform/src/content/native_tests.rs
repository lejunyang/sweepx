use super::*;
use crate::ScanRoot;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // Native Linux content fixtures live on tmpfs so CI's overlay root cannot substitute
        // unknown provider residency for the contract we intend to exercise.
        #[cfg(target_os = "linux")]
        let base = PathBuf::from("/dev/shm");
        #[cfg(not(target_os = "linux"))]
        let base = std::env::temp_dir();
        loop {
            let path = base.join(format!(
                "sweepx-content-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    let path = path.canonicalize().unwrap();
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create controlled content fixture {path:?}: {error}"),
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn platform() -> impl PlatformScanner {
    #[cfg(target_os = "macos")]
    {
        crate::macos::MacosPlatformScanner::new()
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux::LinuxPlatformScanner::new()
    }
    #[cfg(windows)]
    {
        crate::windows::WindowsPlatformScanner::new()
    }
}
fn name(value: &str) -> NativeName {
    #[cfg(unix)]
    {
        NativeName::unix(value.as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        NativeName::windows_utf16(value.encode_utf16().collect::<Vec<_>>())
    }
}
fn request(
    value: &str,
    offset: u64,
    count: u64,
    previous: Option<RegularFileObservation>,
) -> RegularFileStreamRequest {
    RegularFileStreamRequest::new(
        name(value),
        RegularFileReadExpectation::EstablishLive,
        offset,
        count,
        previous,
    )
    .unwrap()
}

#[test]
fn native_content_ranges_full_stream_and_hardlinks_match_ordinary_file_reads() {
    let fixture = Fixture::new();
    let path = fixture.0.join("file");
    let contents: Vec<_> = (0..210_119).map(|i| (i % 241) as u8).collect();
    fs::write(&path, &contents).unwrap();
    fs::hard_link(&path, fixture.0.join("alias")).unwrap();
    let platform = platform();
    let cancel = CancellationToken::new();
    let parent = platform
        .admit_root(&ScanRoot::new(&fixture.0).unwrap(), &cancel)
        .unwrap();
    let mut got = Vec::new();
    let range = stream_bound_regular_file(
        &platform,
        &parent.directory,
        &request("file", 71, 140_005, None),
        &cancel,
        &mut |chunk| {
            got.extend_from_slice(chunk);
            Ok(())
        },
    )
    .unwrap();
    let oracle = fs::read(&path).unwrap();
    assert_eq!(got, oracle[71..140_076]);
    assert_eq!(range.bytes_read, 140_005);
    assert_eq!(
        range.observed_before.logical_bytes.0,
        fs::metadata(&path).unwrap().len() as u128
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(
            range.observed_before.identity,
            crate::EntryIdentity::from_unix(metadata.dev(), metadata.ino())
        );
    }
    got.clear();
    let full = stream_bound_regular_file(
        &platform,
        &parent.directory,
        &request(
            "alias",
            0,
            contents.len() as u64,
            Some(range.observed_after),
        ),
        &cancel,
        &mut |chunk| {
            got.extend_from_slice(chunk);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(got, oracle);
    assert_eq!(full.bytes_read, contents.len() as u64);
    // The operation itself did not write or truncate payloads.
    assert_eq!(fs::read(fixture.0.join("alias")).unwrap(), contents);
}

#[test]
fn native_content_detects_stage_and_in_read_changes_and_cancellation() {
    let fixture = Fixture::new();
    let path = fixture.0.join("file");
    fs::write(&path, vec![1; 170_099]).unwrap();
    let platform = platform();
    let cancel = CancellationToken::new();
    let parent = platform
        .admit_root(&ScanRoot::new(&fixture.0).unwrap(), &cancel)
        .unwrap();
    let first = stream_bound_regular_file(
        &platform,
        &parent.directory,
        &request("file", 0, 10, None),
        &cancel,
        &mut |_| Ok(()),
    )
    .unwrap();
    fs::write(&path, vec![2; 170_099]).unwrap();
    assert!(matches!(
        stream_bound_regular_file(
            &platform,
            &parent.directory,
            &request("file", 0, 10, Some(first.observed_after)),
            &cancel,
            &mut |_| panic!("changed stage emitted bytes")
        ),
        Err(BoundedRegularFileReadError::ChangedDuringRead(_))
    ));
    let mut changed = false;
    assert!(matches!(
        stream_bound_regular_file(
            &platform,
            &parent.directory,
            &request("file", 0, 170_099, None),
            &cancel,
            &mut |_| {
                if !changed {
                    fs::write(&path, vec![3; 170_099]).unwrap();
                    changed = true;
                }
                Ok(())
            }
        ),
        Err(BoundedRegularFileReadError::ChangedDuringRead(_))
    ));
    let mut calls = 0;
    assert_eq!(
        stream_bound_regular_file(
            &platform,
            &parent.directory,
            &request("file", 0, 170_099, None),
            &cancel,
            &mut |_| {
                calls += 1;
                cancel.cancel();
                Ok(())
            }
        )
        .unwrap_err(),
        BoundedRegularFileReadError::Cancelled
    );
    assert_eq!(calls, 1);
}

#[cfg(unix)]
#[test]
fn native_content_refuses_link_substitution_and_identity_mismatch_before_delivery() {
    let fixture = Fixture::new();
    let path = fixture.0.join("file");
    fs::write(&path, b"ordinary payload").unwrap();
    let platform = platform();
    let cancel = CancellationToken::new();
    let parent = platform
        .admit_root(&ScanRoot::new(&fixture.0).unwrap(), &cancel)
        .unwrap();
    let first = stream_bound_regular_file(
        &platform,
        &parent.directory,
        &request("file", 0, 1, None),
        &cancel,
        &mut |_| Ok(()),
    )
    .unwrap();
    fs::rename(&path, fixture.0.join("original")).unwrap();
    fs::write(&path, b"ordinary payload").unwrap();
    let expected = &first.observed_after;
    let bound = RegularFileStreamRequest::new(
        name("file"),
        RegularFileReadExpectation::previously_observed(
            expected.identity.clone(),
            expected.filesystem_identity.clone(),
            expected.mount_identity.clone(),
        ),
        0,
        1,
        None,
    )
    .unwrap();
    assert!(matches!(
        stream_bound_regular_file(
            &platform,
            &parent.directory,
            &bound,
            &cancel,
            &mut |_| panic!("replacement emitted bytes")
        ),
        Err(BoundedRegularFileReadError::IdentityMismatch(_))
    ));
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(fixture.0.join("original"), &path).unwrap();
    assert!(matches!(
        stream_bound_regular_file(
            &platform,
            &parent.directory,
            &request("file", 0, 1, None),
            &cancel,
            &mut |_| panic!("link target emitted bytes")
        ),
        Err(BoundedRegularFileReadError::SymlinkOrReparse { .. })
    ));
    assert_eq!(
        fs::read(fixture.0.join("original")).unwrap(),
        b"ordinary payload"
    );
}
