use super::*;
use crate::{HostPlatformScanner, Scanner, ScannerOptions};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
use sweepx_platform::{
    DirectoryEntryBatch, DirectoryHandleAdmission, DirectoryReadLimits, EntryMetadata,
    PlatformError, RootAdmission,
};

fn fixture() -> (tempfile::TempDir, PathBuf, ScannedEntry) {
    #[cfg(target_os = "linux")]
    let fixture = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fixture.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = fixture.path().to_path_buf();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/file"), b"abcde").unwrap();
    let summary = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan(&[ScanRoot::new(&root).unwrap()], &CancellationToken::new())
        .unwrap();
    let entry = summary
        .entries
        .into_iter()
        .find(|file| file.object_type == ObjectType::File)
        .unwrap();
    (fixture, root, entry)
}
#[test]
fn native_file_content_uses_native_lineage_and_refuses_parent_replacement() {
    let (_fixture, root, mut entry) = fixture();
    entry.display_path = "this display path cannot be used for IO".into();
    let reader = DetailRescanner::new(HostPlatformScanner::new(), ScanResourceLimits::default());
    let cancel = CancellationToken::new();
    let mut bytes = Vec::new();
    let first = reader
        .stream_file(
            FileContentRequest {
                entry: &entry,
                offset: 0,
                max_bytes: 5,
                previous: None,
            },
            &cancel,
            &mut |chunk| {
                bytes.extend_from_slice(chunk);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(bytes, b"abcde");
    fs::rename(root.join("nested"), root.join("original")).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/file"), b"abcde").unwrap();
    assert!(matches!(
        reader.stream_file(
            FileContentRequest {
                entry: &entry,
                offset: 0,
                max_bytes: 5,
                previous: Some(&first.observed_after)
            },
            &cancel,
            &mut |_| panic!("replaced parent emitted payload")
        ),
        Err(FileContentError::Binding(
            DetailRescanError::IdentityMismatch
        ))
    ));
    assert_eq!(fs::read(root.join("original/file")).unwrap(), b"abcde");
}

struct GrowingPlatform {
    host: HostPlatformScanner,
    path: PathBuf,
    grew: AtomicBool,
}
impl PlatformScanner for GrowingPlatform {
    type DirectoryHandle = <HostPlatformScanner as PlatformScanner>::DirectoryHandle;
    fn platform_name(&self) -> &'static str {
        self.host.platform_name()
    }
    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
        self.host.admit_root(root, cancel)
    }
    fn enumerate_children(
        &self,
        directory: &mut Self::DirectoryHandle,
        cancel: &CancellationToken,
        limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError> {
        self.host.enumerate_children(directory, cancel, limits)
    }
    fn inspect_child(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.host.inspect_child(parent, child, cancel)
    }
    fn inspect_child_with_mount_identity(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.host
            .inspect_child_with_mount_identity(parent, child, cancel)
    }
    fn inspect_child_with_directory_admission(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
        admission: DirectoryHandleAdmission,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.host
            .inspect_child_with_directory_admission(parent, child, cancel, admission)
    }
    fn is_same_mount(
        &self,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        self.host.is_same_mount(root, entry)
    }
    fn stream_regular_file_relative(
        &self,
        parent: &Self::DirectoryHandle,
        request: &RegularFileStreamRequest,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
    ) -> Result<RegularFileStreamResult, BoundedRegularFileReadError> {
        if request.max_bytes() == 0 && !self.grew.swap(true, Ordering::SeqCst) {
            fs::write(&self.path, b"abcde-more").unwrap();
        }
        self.host
            .stream_regular_file_relative(parent, request, cancel, consume)
    }
}

#[test]
fn growth_between_inspection_and_content_open_is_refused_before_first_payload() {
    let (_fixture, root, entry) = fixture();
    let reader = DetailRescanner::new(
        GrowingPlatform {
            host: HostPlatformScanner::new(),
            path: root.join("nested/file"),
            grew: AtomicBool::new(false),
        },
        ScanResourceLimits::default(),
    );
    assert!(matches!(
        reader.stream_file(
            FileContentRequest {
                entry: &entry,
                offset: 0,
                max_bytes: 5,
                previous: None
            },
            &CancellationToken::new(),
            &mut |_| panic!("grown file prefix was read")
        ),
        Err(FileContentError::Binding(
            DetailRescanError::IdentityMismatch
        ))
    ));
    assert!(reader.platform.grew.load(Ordering::SeqCst));
    assert_eq!(fs::read(root.join("nested/file")).unwrap(), b"abcde-more");
}
