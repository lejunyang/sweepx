use sweepx_platform::{
    CancellationToken, DirectoryEntryBatch, DirectoryEntryRecord, DirectoryReadLimits,
    EntryMetadata, PlatformError, PlatformScanner, RootAdmission, ScanRoot, WalkEntry,
};

#[derive(Debug, Default, Clone)]
pub struct WindowsPlatformScanner;

impl WindowsPlatformScanner {
    pub fn new() -> Self {
        Self
    }

    fn ensure_not_cancelled(cancel: &CancellationToken) -> Result<(), PlatformError> {
        if cancel.is_cancelled() {
            return Err(PlatformError::Cancelled);
        }
        Ok(())
    }

    #[cfg(windows)]
    fn unsupported() -> PlatformError {
        PlatformError::Unsupported(
            "Windows enumeration and child inspection are disabled until they are implemented entirely through retained no-follow directory handles"
                .to_string(),
        )
    }
}

#[cfg(windows)]
mod backend {
    use std::io;
    use std::mem::{self, MaybeUninit};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::{Path, PathBuf};
    use std::ptr;

    use sweepx_model::NativeName;
    use sweepx_platform::{
        EntryIdentity, EntryKind, FilesystemIdentity, MountIdentity, fingerprint_for, known_count,
        known_u128,
    };
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
        STATUS_NOT_A_DIRECTORY, STATUS_OBJECT_TYPE_MISMATCH, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TRAVERSE, FileAttributeTagInfo,
        FileIdInfo, FileStandardInfo, GetDriveTypeW, GetFileInformationByHandleEx,
        GetVolumeNameForVolumeMountPointW, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE,
    };

    use super::*;

    /// An owned, scan-scoped capability for one admitted Windows directory.
    ///
    /// The handle is intentionally not cloneable. `display_path` is reporting data only and is
    /// never used to regain filesystem authority after admission.
    #[derive(Debug)]
    pub struct WindowsDirectoryHandle {
        handle: OwnedHandle,
        display_path: PathBuf,
    }

    struct ParsedDrivePath {
        drive: u8,
        components: Vec<Vec<u16>>,
    }

    struct ObservedMetadata {
        attributes: u32,
        standard: FILE_STANDARD_INFO,
        file_id: FILE_ID_INFO,
    }

    fn io_error_from_ntstatus(status: i32) -> io::Error {
        // SAFETY: conversion accepts any NTSTATUS and returns the corresponding Win32 error code.
        let win32_error = unsafe { RtlNtStatusToDosError(status) };
        io::Error::from_raw_os_error(win32_error as i32)
    }

    fn get_file_information<T>(handle: &OwnedHandle, class: i32) -> Result<T, io::Error> {
        let mut output = MaybeUninit::<T>::zeroed();
        let size = u32::try_from(mem::size_of::<T>()).expect("Windows metadata structure fits u32");
        // SAFETY: `handle` is live and `output` points to writable storage of exactly `size`
        // bytes for the requested fixed-size information class.
        if unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle() as HANDLE,
                class,
                output.as_mut_ptr().cast(),
                size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: success means the API initialized the requested fixed-size structure.
        Ok(unsafe { output.assume_init() })
    }

    impl WindowsPlatformScanner {
        fn native_name(path: &Path) -> NativeName {
            NativeName::windows_utf16(
                path.file_name()
                    .unwrap_or(path.as_os_str())
                    .encode_wide()
                    .collect::<Vec<_>>(),
            )
        }

        fn parse_drive_path(path: &Path) -> Result<ParsedDrivePath, RootOpenError> {
            // Parse the native units directly. `Path::components` normalizes `.` and repeated
            // separators, which would hide namespace aliases that root admission must reject.
            let mut path_units = path.as_os_str().encode_wide().collect::<Vec<_>>();
            if path_units.len() < 3
                || !u8::try_from(path_units[0]).is_ok_and(|unit| unit.is_ascii_alphabetic())
                || path_units[1] != b':' as u16
                || path_units[2] != b'\\' as u16
                || path_units.contains(&0)
                || path_units.contains(&(b'/' as u16))
            {
                return Err(RootOpenError::UnsupportedNamespace);
            }
            let drive = u8::try_from(path_units[0])
                .expect("validated ASCII drive letter fits u8")
                .to_ascii_uppercase();

            // A single trailing separator is a reporting alias for the same directory. Preserve
            // the caller's display path, but do not turn it into an empty lookup component.
            if path_units.len() > 3 && path_units.last() == Some(&(b'\\' as u16)) {
                path_units.pop();
            }

            let mut components = Vec::new();
            let suffix = &path_units[3..];
            if suffix.is_empty() {
                return Ok(ParsedDrivePath { drive, components });
            }
            for name in suffix.split(|unit| *unit == b'\\' as u16) {
                if name.is_empty()
                    || name.contains(&(b':' as u16))
                    || name == [b'.' as u16]
                    || name == [b'.' as u16, b'.' as u16]
                {
                    return Err(RootOpenError::UnsupportedNamespace);
                }
                components.push(name.to_vec());
            }
            Ok(ParsedDrivePath { drive, components })
        }

        fn drive_root_names(drive: u8) -> ([u16; 4], [u16; 7]) {
            (
                [drive as u16, b':' as u16, b'\\' as u16, 0],
                [
                    b'\\' as u16,
                    b'?' as u16,
                    b'?' as u16,
                    b'\\' as u16,
                    drive as u16,
                    b':' as u16,
                    b'\\' as u16,
                ],
            )
        }

        fn open_drive_volume_root(drive: u8) -> Result<OwnedHandle, RootOpenError> {
            let (dos_root, nt_root) = Self::drive_root_names(drive);
            // Reject network and indeterminate drive mappings before any root traversal.
            if !matches!(
                unsafe { GetDriveTypeW(dos_root.as_ptr()) },
                DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_CDROM | DRIVE_RAMDISK
            ) {
                return Err(RootOpenError::UnsupportedNamespace);
            }

            // Pin the drive designator itself, then require it to identify the same directory as
            // the documented local volume-GUID mapping. This rejects SUBST-style directory roots
            // and avoids using the mutable drive mapping for any descendant lookup.
            let drive_handle = Self::nt_open_directory(ptr::null_mut(), &nt_root)?;
            let drive_metadata = Self::reject_reparse_or_nondirectory(&drive_handle)?;
            let volume_root = Self::volume_guid_nt_path(&dos_root)?;
            let volume_handle = Self::nt_open_directory(ptr::null_mut(), &volume_root)?;
            let volume_metadata = Self::reject_reparse_or_nondirectory(&volume_handle)?;
            if drive_metadata.file_id.VolumeSerialNumber
                != volume_metadata.file_id.VolumeSerialNumber
                || drive_metadata.file_id.FileId.Identifier
                    != volume_metadata.file_id.FileId.Identifier
            {
                return Err(RootOpenError::UnsupportedNamespace);
            }
            Ok(volume_handle)
        }

        fn volume_guid_nt_path(dos_root: &[u16; 4]) -> Result<Vec<u16>, RootOpenError> {
            // A volume GUID path is 49 characters plus NUL today. MAX_PATH-sized storage avoids
            // baking that representation length into the safety boundary.
            let mut volume_name = [0u16; 261];
            if unsafe {
                GetVolumeNameForVolumeMountPointW(
                    dos_root.as_ptr(),
                    volume_name.as_mut_ptr(),
                    u32::try_from(volume_name.len()).expect("volume buffer length fits u32"),
                )
            } == 0
            {
                return Err(RootOpenError::Io(io::Error::last_os_error()));
            }
            let length = volume_name
                .iter()
                .position(|unit| *unit == 0)
                .ok_or(RootOpenError::UnsupportedNamespace)?;
            let volume_name = &volume_name[..length];
            let win32_prefix = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
            if !volume_name.starts_with(&win32_prefix)
                || volume_name.last() != Some(&(b'\\' as u16))
                || volume_name.len() <= win32_prefix.len()
            {
                return Err(RootOpenError::UnsupportedNamespace);
            }
            let mut nt_path = vec![b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];
            nt_path.extend_from_slice(&volume_name[win32_prefix.len()..]);
            Ok(nt_path)
        }

        fn open_child_directory(
            parent: &OwnedHandle,
            component: &[u16],
        ) -> Result<OwnedHandle, RootOpenError> {
            Self::nt_open_directory(parent.as_raw_handle() as HANDLE, component)
        }

        fn nt_open_directory(parent: HANDLE, name: &[u16]) -> Result<OwnedHandle, RootOpenError> {
            let byte_length = name
                .len()
                .checked_mul(mem::size_of::<u16>())
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(RootOpenError::UnsupportedNamespace)?;
            let object_name = UNICODE_STRING {
                Length: byte_length,
                MaximumLength: byte_length,
                Buffer: name.as_ptr().cast_mut(),
            };
            let object_attributes = OBJECT_ATTRIBUTES {
                Length: u32::try_from(mem::size_of::<OBJECT_ATTRIBUTES>())
                    .expect("OBJECT_ATTRIBUTES size fits u32"),
                RootDirectory: parent,
                ObjectName: &object_name,
                Attributes: OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: ptr::null(),
                SecurityQualityOfService: ptr::null(),
            };
            let mut handle: HANDLE = INVALID_HANDLE_VALUE;
            let mut io_status = IO_STATUS_BLOCK::default();
            // SAFETY: `name`, `object_name`, and all other input structures remain live for the
            // call. `parent` is either null for the drive root or a retained live directory
            // handle. On success ownership of the fresh handle transfers to OwnedHandle.
            let status = unsafe {
                NtCreateFile(
                    &mut handle,
                    FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
                    &object_attributes,
                    &mut io_status,
                    ptr::null(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                    ptr::null(),
                    0,
                )
            };
            if status < 0 {
                return if matches!(status, STATUS_NOT_A_DIRECTORY | STATUS_OBJECT_TYPE_MISMATCH) {
                    Err(RootOpenError::NotDirectory)
                } else {
                    Err(RootOpenError::Io(io_error_from_ntstatus(status)))
                };
            }
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(RootOpenError::Io(io::Error::other(
                    "NtCreateFile succeeded without returning a valid handle",
                )));
            }
            // SAFETY: successful NtCreateFile returned a fresh handle and ownership is transferred
            // exactly once.
            Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
        }

        fn reject_reparse_or_nondirectory(
            handle: &OwnedHandle,
        ) -> Result<ObservedMetadata, RootOpenError> {
            let observed = Self::query_metadata(handle).map_err(RootOpenError::Io)?;
            if observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(RootOpenError::ReparsePoint);
            }
            if observed.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || !observed.standard.Directory {
                return Err(RootOpenError::NotDirectory);
            }
            Ok(observed)
        }

        fn resolve_root(
            path: &Path,
            cancel: &CancellationToken,
        ) -> Result<(OwnedHandle, ObservedMetadata), RootOpenError> {
            let parsed = Self::parse_drive_path(path)?;
            let mut handle = Self::open_drive_volume_root(parsed.drive)?;
            let mut observed = Self::reject_reparse_or_nondirectory(&handle)?;
            if cancel.is_cancelled() {
                return Err(RootOpenError::Cancelled);
            }
            for component in parsed.components {
                if cancel.is_cancelled() {
                    return Err(RootOpenError::Cancelled);
                }
                let child = Self::open_child_directory(&handle, &component)?;
                observed = Self::reject_reparse_or_nondirectory(&child)?;
                handle = child;
                if cancel.is_cancelled() {
                    return Err(RootOpenError::Cancelled);
                }
            }
            Ok((handle, observed))
        }

        fn query_metadata(handle: &OwnedHandle) -> Result<ObservedMetadata, io::Error> {
            let attributes: FILE_ATTRIBUTE_TAG_INFO =
                get_file_information(handle, FileAttributeTagInfo)?;
            let standard: FILE_STANDARD_INFO = get_file_information(handle, FileStandardInfo)?;
            let file_id: FILE_ID_INFO = get_file_information(handle, FileIdInfo)?;
            Ok(ObservedMetadata {
                attributes: attributes.FileAttributes,
                standard,
                file_id,
            })
        }

        fn metadata_to_entry(
            path: &Path,
            file_name: NativeName,
            observed: &ObservedMetadata,
        ) -> EntryMetadata {
            let logical_bytes = known_u128(0);
            let allocated_bytes = known_u128(0);
            let identity = EntryIdentity::from_windows_file_id(
                observed.file_id.VolumeSerialNumber,
                observed.file_id.FileId.Identifier,
            );
            let fingerprint =
                fingerprint_for(Some(&identity), &EntryKind::Directory, &logical_bytes);

            EntryMetadata {
                path: path.to_path_buf(),
                file_name,
                kind: EntryKind::Directory,
                // Directories do not contribute file content bytes. File sizes remain a later
                // child-inspection concern, so root admission reports exact zero conservatively.
                logical_bytes,
                allocated_bytes,
                hard_link_count: known_count(u128::from(observed.standard.NumberOfLinks)),
                fingerprint,
                identity: Some(identity),
                filesystem_identity: Some(FilesystemIdentity {
                    device: observed.file_id.VolumeSerialNumber,
                }),
                mount_identity: Some(MountIdentity {
                    value: observed.file_id.VolumeSerialNumber,
                }),
                hard_link_key: None,
            }
        }
    }

    #[derive(Debug)]
    enum RootOpenError {
        Cancelled,
        ReparsePoint,
        NotDirectory,
        UnsupportedNamespace,
        Io(io::Error),
    }

    impl PlatformScanner for WindowsPlatformScanner {
        type DirectoryHandle = WindowsDirectoryHandle;

        fn platform_name(&self) -> &'static str {
            "windows"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            if !root.path().is_absolute() {
                return Err(PlatformError::RootRejected(format!(
                    "root is not absolute: {}",
                    root.path().display()
                )));
            }
            let root_locator = root.native_absolute_path().map_err(|error| {
                PlatformError::RootRejected(format!(
                    "root has no valid native absolute representation: {error}"
                ))
            })?;

            let (handle, observed) =
                Self::resolve_root(root.path(), cancel).map_err(|error| match error {
                    RootOpenError::Cancelled => PlatformError::Cancelled,
                    RootOpenError::ReparsePoint => PlatformError::RootRejected(format!(
                        "root path contains a reparse point: {}",
                        root.path().display()
                    )),
                    RootOpenError::NotDirectory => PlatformError::RootRejected(format!(
                        "root is not a directory: {}",
                        root.path().display()
                    )),
                    RootOpenError::UnsupportedNamespace => PlatformError::RootRejected(format!(
                        "root must use an ordinary local drive-letter path without dot components: {}",
                        root.path().display()
                    )),
                    RootOpenError::Io(error) => PlatformError::io(root.path(), error),
                })?;
            Self::ensure_not_cancelled(cancel)?;
            if observed.file_id.VolumeSerialNumber == 0
                || observed.file_id.FileId.Identifier == [0; 16]
            {
                return Err(PlatformError::RootRejected(format!(
                    "root filesystem did not provide an authoritative volume and file identity: {}",
                    root.path().display()
                )));
            }

            let metadata =
                Self::metadata_to_entry(root.path(), Self::native_name(root.path()), &observed);
            Ok(RootAdmission::new(
                root.clone(),
                metadata,
                WindowsDirectoryHandle {
                    handle,
                    display_path: root.path().to_path_buf(),
                },
                root_locator,
            ))
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            _limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            let _ = (&directory.handle, &directory.display_path);
            Err(Self::unsupported())
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            _child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            let _ = (&parent.handle, &parent.display_path);
            Err(Self::unsupported())
        }

        fn is_same_mount(
            &self,
            _root: &EntryMetadata,
            _entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            Err(Self::unsupported())
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        use sweepx_model::EvidenceValue;

        use super::*;

        #[derive(Debug)]
        struct TempDir(PathBuf);

        impl TempDir {
            fn new(label: &str) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "sweepx-windows-root-{label}-{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("system clock is after the Unix epoch")
                        .as_nanos()
                ));
                fs::create_dir(&path).expect("temporary directory is created");
                Self(path)
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn scanner() -> WindowsPlatformScanner {
            WindowsPlatformScanner::new()
        }

        #[test]
        fn parses_and_admits_exact_drive_root() {
            let current = std::env::current_dir().expect("current directory is available");
            let current_units = current.as_os_str().encode_wide().collect::<Vec<_>>();
            assert!(current_units.len() >= 3, "current path has a drive prefix");
            let drive_root = PathBuf::from(format!(
                "{}:\\",
                char::from(u8::try_from(current_units[0]).expect("current drive letter is ASCII"))
            ));
            let parsed = WindowsPlatformScanner::parse_drive_path(&drive_root)
                .expect("exact drive root parses");
            assert!(parsed.components.is_empty());

            let requested = ScanRoot::new(drive_root).expect("drive root is absolute");
            let admission = scanner()
                .admit_root(&requested, &CancellationToken::new())
                .expect("local drive root is admitted");
            admission
                .validate_for_root(&requested)
                .expect("drive-root admission remains bound");
        }

        #[test]
        fn admits_ordinary_directory_with_full_handle_identity() {
            let root = TempDir::new("ordinary");
            let requested = ScanRoot::new(root.0.clone()).expect("root is absolute");
            let admission = scanner()
                .admit_root(&requested, &CancellationToken::new())
                .expect("ordinary directory is admitted");

            admission
                .validate_for_root(&requested)
                .expect("admission is bound to the requested root");
            let identity = admission
                .metadata
                .identity
                .as_ref()
                .expect("file id is known");
            assert_ne!(identity.windows_file_id(), [0; 16]);
            assert_ne!(identity.device(), 0);
            assert_eq!(
                admission
                    .metadata
                    .filesystem_identity
                    .as_ref()
                    .map(|value| value.device),
                Some(identity.device())
            );
            assert_eq!(
                admission
                    .metadata
                    .mount_identity
                    .as_ref()
                    .map(|value| value.value),
                Some(identity.device())
            );
            assert!(matches!(
                admission.metadata.logical_bytes,
                EvidenceValue::Known { value } if u128::from(value) == 0
            ));
            assert!(matches!(
                admission.metadata.allocated_bytes,
                EvidenceValue::Known { value } if u128::from(value) == 0
            ));
            assert!(matches!(
                admission.metadata.hard_link_count,
                EvidenceValue::Known { value } if u128::from(value) >= 1
            ));
        }

        #[test]
        fn rejects_final_directory_symlink_when_creation_is_permitted() {
            let root = TempDir::new("symlink");
            let target = root.0.join("target");
            let link = root.0.join("link");
            fs::create_dir(&target).expect("target directory is created");
            match std::os::windows::fs::symlink_dir(&target, &link) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
                Err(error) => panic!("directory symlink creation failed: {error}"),
            }

            let result = scanner().admit_root(
                &ScanRoot::new(link).expect("link path is absolute"),
                &CancellationToken::new(),
            );
            assert!(matches!(result, Err(PlatformError::RootRejected(_))));
        }

        #[test]
        fn rejects_intermediate_directory_symlink_when_creation_is_permitted() {
            let root = TempDir::new("intermediate-symlink");
            let target = root.0.join("target");
            let nested = target.join("nested");
            let link = root.0.join("link");
            fs::create_dir_all(&nested).expect("target hierarchy is created");
            match std::os::windows::fs::symlink_dir(&target, &link) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
                Err(error) => panic!("directory symlink creation failed: {error}"),
            }

            let result = scanner().admit_root(
                &ScanRoot::new(link.join("nested")).expect("path is absolute"),
                &CancellationToken::new(),
            );
            assert!(matches!(result, Err(PlatformError::RootRejected(_))));
        }

        #[test]
        fn retained_handle_survives_path_rename_and_replacement() {
            let container = TempDir::new("retained");
            let original = container.0.join("root");
            let renamed = container.0.join("renamed");
            fs::create_dir(&original).expect("original directory is created");
            let requested = ScanRoot::new(original.clone()).expect("root is absolute");
            let admission = scanner()
                .admit_root(&requested, &CancellationToken::new())
                .expect("ordinary directory is admitted");
            let expected = admission.metadata.identity.clone();

            fs::rename(&original, &renamed).expect("admitted directory can be renamed");
            fs::create_dir(&original).expect("replacement directory is created");

            let observed = WindowsPlatformScanner::query_metadata(&admission.directory.handle)
                .expect("metadata remains readable from retained handle");
            let retained_identity = EntryIdentity::from_windows_file_id(
                observed.file_id.VolumeSerialNumber,
                observed.file_id.FileId.Identifier,
            );
            assert_eq!(Some(retained_identity), expected);

            let replacement = scanner()
                .admit_root(&requested, &CancellationToken::new())
                .expect("replacement directory is independently admitted");
            assert_ne!(replacement.metadata.identity, expected);
        }

        #[test]
        fn cancellation_precedes_path_validation_and_io() {
            let cancel = CancellationToken::new();
            cancel.cancel();
            let forged_relative_root = ScanRoot {
                path: PathBuf::from("relative-root"),
            };

            assert!(matches!(
                scanner().admit_root(&forged_relative_root, &cancel),
                Err(PlatformError::Cancelled)
            ));
        }

        #[test]
        fn rejects_forged_relative_root_without_io() {
            let forged_relative_root = ScanRoot {
                path: PathBuf::from("relative-root"),
            };

            assert!(matches!(
                scanner().admit_root(&forged_relative_root, &CancellationToken::new()),
                Err(PlatformError::RootRejected(_))
            ));
        }

        #[test]
        fn rejects_unc_and_device_namespaces() {
            for path in [
                PathBuf::from(r"\server\share\root"),
                PathBuf::from(r"\?\C:\root"),
                PathBuf::from(r"\.\C:\root"),
                PathBuf::from(r"C:/root"),
                PathBuf::from(r"C:\root\.\child"),
                PathBuf::from(r"C:\root\..\child"),
                PathBuf::from(r"C:\root\\child"),
            ] {
                let forged_root = ScanRoot { path };
                assert!(matches!(
                    scanner().admit_root(&forged_root, &CancellationToken::new()),
                    Err(PlatformError::RootRejected(_))
                ));
            }
        }

        #[test]
        fn rejects_regular_file_as_root() {
            let container = TempDir::new("regular-file");
            let file = container.0.join("file");
            fs::write(&file, b"not a directory").expect("regular file is created");

            assert!(matches!(
                scanner().admit_root(
                    &ScanRoot::new(file).expect("file path is absolute"),
                    &CancellationToken::new(),
                ),
                Err(PlatformError::RootRejected(_))
            ));
        }

        #[test]
        fn child_operations_remain_unsupported_after_admission() {
            let root = TempDir::new("unsupported-children");
            let requested = ScanRoot::new(root.0.clone()).expect("root is absolute");
            let mut admission = scanner()
                .admit_root(&requested, &CancellationToken::new())
                .expect("ordinary directory is admitted");
            let child = DirectoryEntryRecord {
                path: root.0.join("child"),
                file_name: NativeName::windows_utf16("child".encode_utf16().collect::<Vec<_>>()),
            };

            assert!(matches!(
                scanner().enumerate_children(
                    &mut admission.directory,
                    &CancellationToken::new(),
                    DirectoryReadLimits {
                        max_batch_entries: 1,
                        max_batch_bytes: 1024,
                    },
                ),
                Err(PlatformError::Unsupported(_))
            ));
            assert!(matches!(
                scanner().inspect_child(&admission.directory, &child, &CancellationToken::new(),),
                Err(PlatformError::Unsupported(_))
            ));
            assert!(matches!(
                scanner().is_same_mount(&admission.metadata, &admission.metadata),
                Err(PlatformError::Unsupported(_))
            ));
        }
    }
}

#[cfg(not(windows))]
mod backend {
    use super::*;

    /// Placeholder used only when this platform crate is checked on a non-Windows host.
    #[derive(Debug)]
    pub struct WindowsDirectoryHandle;

    impl PlatformScanner for WindowsPlatformScanner {
        type DirectoryHandle = WindowsDirectoryHandle;

        fn platform_name(&self) -> &'static str {
            "windows"
        }

        fn admit_root(
            &self,
            _root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            Err(PlatformError::Unsupported(
                "Windows scanner backend is unavailable on this host".to_string(),
            ))
        }

        fn enumerate_children(
            &self,
            _directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            _limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            Err(PlatformError::Unsupported(
                "Windows scanner backend is unavailable on this host".to_string(),
            ))
        }

        fn inspect_child(
            &self,
            _parent: &Self::DirectoryHandle,
            _child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            Err(PlatformError::Unsupported(
                "Windows scanner backend is unavailable on this host".to_string(),
            ))
        }

        fn is_same_mount(
            &self,
            _root: &EntryMetadata,
            _entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            Err(PlatformError::Unsupported(
                "Windows scanner backend is unavailable on this host".to_string(),
            ))
        }
    }
}

pub use backend::WindowsDirectoryHandle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_as_windows_backend() {
        assert_eq!(WindowsPlatformScanner::new().platform_name(), "windows");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_placeholder_preserves_cancellation_precedence() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let root = ScanRoot::new(std::env::current_dir().expect("current directory is available"))
            .expect("current directory is absolute");

        assert!(matches!(
            WindowsPlatformScanner::new().admit_root(&root, &cancel),
            Err(PlatformError::Cancelled)
        ));
    }
}
