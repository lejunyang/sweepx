use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sweepx_model::{NativeName, ReasonCode};
use sweepx_platform::{
    BoundaryKind, BoundaryRecord, CancellationToken, DirectoryEntryRecord, EntryIdentity,
    EntryKind, EntryMetadata, ErrorRecord, FilesystemIdentity, HardLinkKey, MountIdentity,
    PlatformError, PlatformScanner, RootAdmission, ScanRoot, WalkEntry, error_kind_for_io,
    fingerprint_for, known_count, known_u128, reason_for_io,
};

// Native mutation remains a test-only qualification concern. In particular,
// this module is absent from normal and all-features library builds.
#[cfg(all(test, target_os = "linux"))]
mod trash_qualification;

#[derive(Debug, Default, Clone)]
pub struct LinuxPlatformScanner;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfoSnapshot {
    by_mount_point: BTreeMap<PathBuf, u64>,
}

impl MountInfoSnapshot {
    fn capture() -> Result<Self, PlatformError> {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")
            .map_err(|error| PlatformError::io(PathBuf::from("/proc/self/mountinfo"), error))?;
        let mut by_mount_point = BTreeMap::new();
        for line in mountinfo.lines() {
            let mut fields = line.split(" - ");
            let left = match fields.next() {
                Some(value) => value,
                None => continue,
            };

            let left_fields: Vec<&str> = left.split_whitespace().collect();
            if left_fields.len() < 5 {
                continue;
            }

            let mount_id = match left_fields[0].parse::<u64>() {
                Ok(value) => value,
                Err(_) => continue,
            };
            let mount_point = PathBuf::from(left_fields[4].replace("\\040", " "));
            by_mount_point.insert(mount_point, mount_id);
        }
        Ok(Self { by_mount_point })
    }

    fn mount_id_for_path(&self, path: &Path) -> Option<u64> {
        let path_bytes = path.as_os_str().as_bytes();
        let mut best: Option<(usize, u64)> = None;
        for (mount_point, mount_id) in &self.by_mount_point {
            let mount_bytes = mount_point.as_os_str().as_bytes();
            let is_match = path_bytes == mount_bytes
                || (path_bytes.starts_with(mount_bytes) && mount_bytes.last() == Some(&b'/'))
                || (path_bytes.starts_with(mount_bytes)
                    && path_bytes
                        .get(mount_bytes.len())
                        .is_some_and(|byte| *byte == b'/'));
            if !is_match {
                continue;
            }

            let candidate = (mount_bytes.len(), *mount_id);
            if best.as_ref().is_none_or(|current| candidate.0 > current.0) {
                best = Some(candidate);
            }
        }

        best.map(|(_, mount_id)| mount_id)
    }
}

impl LinuxPlatformScanner {
    pub fn new() -> Self {
        Self
    }

    fn ensure_not_cancelled(cancel: &CancellationToken) -> Result<(), PlatformError> {
        if cancel.is_cancelled() {
            return Err(PlatformError::Cancelled);
        }
        Ok(())
    }

    fn native_name(path: &Path) -> NativeName {
        let name = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .as_bytes()
            .to_vec();
        NativeName::unix(name)
    }

    fn metadata_to_entry(
        path: &Path,
        file_name: NativeName,
        metadata: fs::Metadata,
        mount_snapshot: Option<&MountInfoSnapshot>,
    ) -> EntryMetadata {
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            EntryKind::Directory
        } else if file_type.is_file() {
            EntryKind::File
        } else if file_type.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::Other
        };

        let logical_bytes = if file_type.is_file() {
            known_u128(u128::from(metadata.len()))
        } else {
            known_u128(0)
        };

        let allocated_bytes = if file_type.is_file() {
            known_u128(u128::from(metadata.blocks()) * 512)
        } else {
            known_u128(0)
        };

        let identity = Some(EntryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        let filesystem_identity = Some(FilesystemIdentity {
            device: metadata.dev(),
        });
        let mount_identity = mount_snapshot
            .and_then(|snapshot| snapshot.mount_id_for_path(path))
            .map(|value| MountIdentity { value });
        let hard_link_key = if file_type.is_file() {
            Some(HardLinkKey {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        } else {
            None
        };
        let hard_link_count = known_count(u128::from(metadata.nlink()));
        let fingerprint = fingerprint_for(identity.as_ref(), &kind, &logical_bytes);

        EntryMetadata {
            path: path.to_path_buf(),
            file_name,
            kind,
            logical_bytes,
            allocated_bytes,
            hard_link_count,
            fingerprint,
            identity,
            filesystem_identity,
            mount_identity,
            hard_link_key,
        }
    }
}

impl PlatformScanner for LinuxPlatformScanner {
    fn platform_name(&self) -> &'static str {
        "linux"
    }

    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission, PlatformError> {
        Self::ensure_not_cancelled(cancel)?;

        let metadata = fs::symlink_metadata(root.path())
            .map_err(|error| PlatformError::io(root.path(), error))?;
        Self::ensure_not_cancelled(cancel)?;
        if metadata.file_type().is_symlink() {
            return Err(PlatformError::RootRejected(format!(
                "root is a symlink and cannot be scanned: {}",
                root.path().display()
            )));
        }
        if !metadata.file_type().is_dir() {
            return Err(PlatformError::RootRejected(format!(
                "root is not a directory: {}",
                root.path().display()
            )));
        }

        let mount_snapshot = MountInfoSnapshot::capture().ok();
        let entry = Self::metadata_to_entry(
            root.path(),
            Self::native_name(root.path()),
            metadata,
            mount_snapshot.as_ref(),
        );
        Ok(RootAdmission {
            root: root.clone(),
            metadata: entry,
        })
    }

    fn read_dir_entries(
        &self,
        path: &Path,
        cancel: &CancellationToken,
        max_entries: usize,
    ) -> Result<Vec<DirectoryEntryRecord>, PlatformError> {
        Self::ensure_not_cancelled(cancel)?;

        let mut entries = Vec::new();
        let read_dir = fs::read_dir(path).map_err(|error| PlatformError::io(path, error))?;
        for entry in read_dir {
            Self::ensure_not_cancelled(cancel)?;
            if entries.len() >= max_entries {
                return Err(PlatformError::ResourceLimit(format!(
                    "directory entry cap exceeded at {}",
                    path.display()
                )));
            }
            let entry = entry.map_err(|error| PlatformError::io(path, error))?;
            let child_path = entry.path();
            let file_name = NativeName::unix(entry.file_name().as_bytes().to_vec());
            entries.push(DirectoryEntryRecord {
                path: child_path,
                file_name,
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }

    fn stat_entry(
        &self,
        path: &Path,
        file_name: NativeName,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry, PlatformError> {
        Self::ensure_not_cancelled(cancel)?;

        let metadata = match fs::symlink_metadata(path) {
            Ok(value) => value,
            Err(error) => {
                return Ok(WalkEntry::Error(ErrorRecord {
                    path: path.to_path_buf(),
                    kind: error_kind_for_io(&error),
                    reason: reason_for_io(&error),
                    detail: error.to_string(),
                }));
            }
        };

        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let entry = EntryMetadata {
                path: path.to_path_buf(),
                file_name,
                kind: EntryKind::Symlink,
                logical_bytes: known_u128(0),
                allocated_bytes: known_u128(0),
                hard_link_count: known_count(1),
                fingerprint: fingerprint_for(None, &EntryKind::Symlink, &known_u128(0)),
                identity: None,
                filesystem_identity: None,
                mount_identity: None,
                hard_link_key: None,
            };
            return Ok(WalkEntry::Link(entry));
        }

        let mount_snapshot = MountInfoSnapshot::capture().ok();
        let entry = Self::metadata_to_entry(path, file_name, metadata, mount_snapshot.as_ref());
        match entry.kind {
            EntryKind::Directory => Ok(WalkEntry::Directory(entry)),
            EntryKind::File => Ok(WalkEntry::File(entry)),
            EntryKind::ReparsePoint => Ok(WalkEntry::Boundary(BoundaryRecord {
                path: path.to_path_buf(),
                kind: BoundaryKind::ReparsePoint,
                reason: ReasonCode::UnsupportedFilesystem,
                detail: "directory reparse points are unsupported on linux backend".to_string(),
            })),
            EntryKind::Symlink => Ok(WalkEntry::Link(entry)),
            EntryKind::Other => Ok(WalkEntry::Boundary(BoundaryRecord {
                path: path.to_path_buf(),
                kind: BoundaryKind::OtherFilesystem,
                reason: ReasonCode::UnsupportedFilesystem,
                detail: "special filesystem entry rejected".to_string(),
            })),
        }
    }

    fn is_same_mount(
        &self,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        match (&root.mount_identity, &entry.mount_identity) {
            (Some(left), Some(right)) => Ok(left == right),
            _ => Err(PlatformError::Unsupported(
                "mount identity unavailable".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use tempfile::TempDir;

    #[test]
    fn reject_root_symlink() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let root = ScanRoot::new(link).unwrap();
        let error = scanner
            .admit_root(&root, &CancellationToken::new())
            .unwrap_err();
        assert!(matches!(error, PlatformError::RootRejected(_)));
    }

    #[test]
    fn stat_reports_symlink_as_link_entry() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"payload").unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let entry = scanner
            .stat_entry(
                &link,
                NativeName::unix(b"link".to_vec()),
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(entry, WalkEntry::Link(_)));
    }

    #[test]
    fn admit_root_honors_cancellation() {
        let temp = TempDir::new().unwrap();
        let root_dir = temp.path().join("root");
        fs::create_dir(&root_dir).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = scanner
            .admit_root(&ScanRoot::new(root_dir).unwrap(), &cancel)
            .unwrap_err();
        assert!(matches!(error, PlatformError::Cancelled));
    }

    #[test]
    fn file_metadata_reports_hard_link_identity() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("file");
        fs::write(&file, b"hello world").unwrap();
        let second = temp.path().join("second");
        fs::hard_link(&file, &second).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let first = scanner
            .stat_entry(
                &file,
                NativeName::unix(b"file".to_vec()),
                &CancellationToken::new(),
            )
            .unwrap();
        let second = scanner
            .stat_entry(
                &second,
                NativeName::unix(b"second".to_vec()),
                &CancellationToken::new(),
            )
            .unwrap();

        let WalkEntry::File(first) = first else {
            panic!("expected file entry");
        };
        let WalkEntry::File(second) = second else {
            panic!("expected file entry");
        };
        assert_eq!(first.hard_link_key, second.hard_link_key);
        assert_eq!(first.allocated_bytes, second.allocated_bytes);
    }

    #[test]
    fn cancellation_stops_read_dir() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("child")).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = scanner
            .read_dir_entries(temp.path(), &cancel, 16)
            .unwrap_err();
        assert!(matches!(error, PlatformError::Cancelled));
    }

    #[test]
    fn read_dir_enforces_entry_cap() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("a"), b"a").unwrap();
        fs::write(temp.path().join("b"), b"b").unwrap();

        let scanner = LinuxPlatformScanner::new();
        let error = scanner
            .read_dir_entries(temp.path(), &CancellationToken::new(), 1)
            .unwrap_err();
        assert!(matches!(error, PlatformError::ResourceLimit(_)));
    }
}
