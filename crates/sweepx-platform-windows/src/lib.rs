#[cfg(windows)]
use sweepx_platform::DirectoryHandleAdmission;
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
}

#[cfg(windows)]
mod backend {
    use std::io;
    use std::mem::{self, MaybeUninit};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::{Path, PathBuf};
    use std::ptr;

    use sweepx_model::{NativeName, ReasonCode};
    use sweepx_platform::{
        BoundaryKind, BoundaryRecord, EntryIdentity, EntryKind, ErrorRecord, FilesystemIdentity,
        HardLinkKey, MountIdentity, OpenedDirectory, error_kind_for_io, fingerprint_for,
        known_count, known_u128, reason_for_io, unknown_u128,
    };
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_ID_EXTD_DIR_INFORMATION, FILE_OPEN, FILE_OPEN_NO_RECALL,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileIdExtdDirectoryInformation,
        NtCreateFile, NtQueryDirectoryFile, RtlIsDosDeviceName_U,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError,
        STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_FILE_IS_A_DIRECTORY,
        STATUS_INFO_LENGTH_MISMATCH, STATUS_NO_MORE_FILES, STATUS_NOT_A_DIRECTORY,
        STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
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
    /// never used to regain filesystem authority after admission. Native filesystem calls are
    /// synchronous, so cancellation is cooperative between calls rather than preempting one.
    #[derive(Debug)]
    pub struct WindowsDirectoryHandle {
        handle: OwnedHandle,
        display_path: PathBuf,
        identity: ObjectIdentity,
        cursor: DirectoryCursor,
        inspection_batch: Vec<EnumeratedChildEvidence>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ObjectIdentity {
        volume: u64,
        file_id: [u8; 16],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct EnumeratedIdentity {
        file_id: [u8; 16],
        is_directory: bool,
        is_reparse: bool,
        reparse_tag: u32,
    }

    #[derive(Debug)]
    struct EnumeratedChild {
        record: DirectoryEntryRecord,
        identity: EnumeratedIdentity,
    }

    #[derive(Debug)]
    struct EnumeratedChildEvidence {
        file_name: NativeName,
        identity: EnumeratedIdentity,
    }

    #[derive(Debug)]
    enum DirectoryCursor {
        NotStarted,
        Active {
            restart_scan: bool,
            pending: Option<EnumeratedChild>,
        },
        Exhausted,
    }

    struct ParsedDrivePath {
        drive: u8,
        components: Vec<Vec<u16>>,
    }

    struct ObservedMetadata {
        attributes: u32,
        reparse_tag: u32,
        standard: FILE_STANDARD_INFO,
        file_id: FILE_ID_INFO,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DirectoryOpenRole {
        Ancestor,
        AdmittedRoot,
    }

    impl DirectoryOpenRole {
        const fn desired_access(self) -> u32 {
            let access = FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;
            match self {
                Self::Ancestor => access,
                Self::AdmittedRoot => access | FILE_LIST_DIRECTORY,
            }
        }
    }

    const DIRECTORY_QUERY_BUFFER_BYTES: usize = 64 * 1024;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DirectoryQueryOutcome {
        Record { bytes_returned: usize },
        Exhausted,
    }

    fn object_identity(observed: &ObservedMetadata) -> ObjectIdentity {
        ObjectIdentity {
            volume: observed.file_id.VolumeSerialNumber,
            file_id: observed.file_id.FileId.Identifier,
        }
    }

    fn same_object(left: &ObservedMetadata, right: &ObservedMetadata) -> bool {
        object_identity(left) == object_identity(right)
            && (left.attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
                == (right.attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
            && (left.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
                == (right.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            && left.reparse_tag == right.reparse_tag
            && WindowsPlatformScanner::is_provider_boundary(left.attributes)
                == WindowsPlatformScanner::is_provider_boundary(right.attributes)
    }

    fn matches_enumerated_identity(
        volume: u64,
        expected: &EnumeratedIdentity,
        observed: &ObservedMetadata,
    ) -> bool {
        volume == observed.file_id.VolumeSerialNumber
            && expected.file_id != [0; 16]
            && expected.file_id == observed.file_id.FileId.Identifier
            && expected.is_directory == (observed.attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
            && expected.is_directory == observed.standard.Directory
            && expected.is_reparse == (observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            && (!expected.is_reparse || expected.reparse_tag == observed.reparse_tag)
    }

    fn verify_enumerated_identity(
        volume: u64,
        expected: &EnumeratedIdentity,
        observed: &ObservedMetadata,
    ) -> Result<(), io::Error> {
        if matches_enumerated_identity(volume, expected, observed) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "child identity, type, or reparse tag changed after enumeration",
            ))
        }
    }

    fn take_bounded_entry(
        pending: &mut Option<EnumeratedChild>,
        entries: &mut Vec<DirectoryEntryRecord>,
        admitted: &mut Vec<EnumeratedChildEvidence>,
        retained_bytes: &mut usize,
        child: EnumeratedChild,
        limits: DirectoryReadLimits,
        directory_path: &Path,
    ) -> Result<Option<DirectoryEntryBatch>, PlatformError> {
        let record_bytes = child.record.estimated_retained_bytes().ok_or_else(|| {
            PlatformError::ResourceLimit(format!(
                "directory byte accounting overflow at {}",
                directory_path.display()
            ))
        })?;
        let next_bytes = retained_bytes.checked_add(record_bytes).ok_or_else(|| {
            PlatformError::ResourceLimit(format!(
                "directory byte accounting overflow at {}",
                directory_path.display()
            ))
        })?;
        if entries.is_empty() && record_bytes > limits.max_batch_bytes {
            *pending = Some(child);
            return Err(PlatformError::ResourceLimit(format!(
                "single directory entry exceeds the retained-byte cap at {}",
                directory_path.display()
            )));
        }
        if entries.len() >= limits.max_batch_entries || next_bytes > limits.max_batch_bytes {
            *pending = Some(child);
            return Ok(Some(DirectoryEntryBatch::continued(mem::take(entries))));
        }
        *retained_bytes = next_bytes;
        admitted.push(EnumeratedChildEvidence {
            file_name: child.record.file_name.clone(),
            identity: child.identity,
        });
        entries.push(child.record);
        Ok(None)
    }

    fn validate_directory_query_lengths(
        record_bytes: usize,
        next_entry_offset: u32,
        name_bytes: u32,
    ) -> Result<(usize, usize), io::Error> {
        let fixed_bytes = mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        if record_bytes < fixed_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NtQueryDirectoryFile returned an invalid record length",
            ));
        }
        if next_entry_offset != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "single-entry directory query returned an unexpected continuation offset",
            ));
        }
        let name_bytes = usize::try_from(name_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid filename length"))?;
        if name_bytes % mem::size_of::<u16>() != 0
            || fixed_bytes
                .checked_add(name_bytes)
                .is_none_or(|required| required > record_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NtQueryDirectoryFile returned a truncated filename",
            ));
        }
        Ok((fixed_bytes, name_bytes))
    }

    fn read_directory_query_field<T: Copy>(
        buffer: &[u8],
        offset: usize,
        field_name: &str,
    ) -> Result<T, io::Error> {
        let end = offset.checked_add(mem::size_of::<T>()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("directory query field offset overflow: {field_name}"),
            )
        })?;
        if end > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("directory query record omitted field: {field_name}"),
            ));
        }
        // SAFETY: the complete field byte range was bounds-checked above. read_unaligned accepts
        // arbitrary input alignment and copies the field value without reading adjacent bytes.
        Ok(unsafe { ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<T>()) })
    }

    fn directory_query_outcome(
        status: i32,
        information: usize,
        buffer_capacity: usize,
        cancel: &CancellationToken,
        directory_path: &Path,
    ) -> Result<DirectoryQueryOutcome, PlatformError> {
        // This check intentionally precedes interpreting success, EOF, and failure statuses so
        // cancellation observed during the synchronous native call always wins.
        WindowsPlatformScanner::ensure_not_cancelled(cancel)?;
        if status == STATUS_NO_MORE_FILES || (status == STATUS_SUCCESS && information == 0) {
            return Ok(DirectoryQueryOutcome::Exhausted);
        }
        if matches!(
            status,
            STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL | STATUS_INFO_LENGTH_MISMATCH
        ) {
            return Err(PlatformError::io(
                directory_path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry exceeds the bounded native query buffer",
                ),
            ));
        }
        if status != STATUS_SUCCESS {
            return Err(PlatformError::io(
                directory_path,
                io_error_from_ntstatus(status),
            ));
        }
        let fixed_bytes = mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        if information < fixed_bytes || information > buffer_capacity {
            return Err(PlatformError::io(
                directory_path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NtQueryDirectoryFile returned an invalid record length",
                ),
            ));
        }
        Ok(DirectoryQueryOutcome::Record {
            bytes_returned: information,
        })
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
                    || name == [b'.' as u16]
                    || name == [b'.' as u16, b'.' as u16]
                    || name.iter().copied().any(|unit| {
                        unit <= 31
                            || matches!(
                                unit,
                                0x0022
                                    | 0x002a
                                    | 0x002f
                                    | 0x003a
                                    | 0x003c
                                    | 0x003e
                                    | 0x003f
                                    | 0x005c
                                    | 0x007c
                            )
                    })
                    || name
                        .last()
                        .is_some_and(|unit| matches!(*unit, 0x002e | 0x0020))
                    || Self::is_reserved_dos_device_name(name)
                {
                    return Err(RootOpenError::UnsupportedNamespace);
                }
                components.push(name.to_vec());
            }
            Ok(ParsedDrivePath { drive, components })
        }

        fn is_reserved_dos_device_name(component: &[u16]) -> bool {
            // Win32 resolves DOS device aliases case-insensitively and before considering an
            // extension. Relative NtCreateFile opens do neither, so admitting such a spelling
            // would bind the capability to a different object than ordinary Win32 callers name.
            let stem_end = component
                .iter()
                .position(|unit| *unit == b'.' as u16)
                .unwrap_or(component.len());
            let stem = &component[..stem_end];
            let stem = &stem[..stem
                .iter()
                .rposition(|unit| *unit != b' ' as u16)
                .map_or(0, |index| index + 1)];

            fn ascii_eq_ignore_case(actual: &[u16], expected: &[u8]) -> bool {
                actual.len() == expected.len()
                    && actual.iter().zip(expected).all(|(actual, expected)| {
                        u8::try_from(*actual)
                            .is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
                    })
            }

            // CLOCK$ is a legacy DOS device alias even though current RtlIsDosDeviceName_U
            // implementations do not consistently report it.
            if ascii_eq_ignore_case(stem, b"CLOCK$") {
                return true;
            }
            if stem.len() == 4
                && matches!(stem[3], 0x00b9 | 0x00b2 | 0x00b3)
                && (ascii_eq_ignore_case(&stem[..3], b"COM")
                    || ascii_eq_ignore_case(&stem[..3], b"LPT"))
            {
                return true;
            }
            let mut nul_terminated = Vec::with_capacity(stem.len() + 1);
            nul_terminated.extend_from_slice(stem);
            nul_terminated.push(0);

            // SAFETY: the component parser rejects interior NULs, and this owned buffer remains
            // live and NUL-terminated for the duration of the call. Using the Windows routine
            // keeps case folding and the superscript-digit aliases aligned with Win32 itself.
            unsafe { RtlIsDosDeviceName_U(nul_terminated.as_ptr()) != 0 }
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

        fn open_drive_volume_root(
            drive: u8,
            volume_role: DirectoryOpenRole,
        ) -> Result<OwnedHandle, RootOpenError> {
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
            let drive_handle = Self::nt_open_directory(
                ptr::null_mut(),
                &nt_root,
                DirectoryOpenRole::Ancestor,
                true,
            )?;
            let drive_metadata = Self::reject_reparse_or_nondirectory(&drive_handle)?;
            let volume_root = Self::volume_guid_nt_path(&dos_root)?;
            let volume_handle =
                Self::nt_open_directory(ptr::null_mut(), &volume_root, volume_role, true)?;
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
            role: DirectoryOpenRole,
            case_insensitive: bool,
        ) -> Result<OwnedHandle, RootOpenError> {
            Self::nt_open_directory(
                parent.as_raw_handle() as HANDLE,
                component,
                role,
                case_insensitive,
            )
        }

        fn nt_open_directory(
            parent: HANDLE,
            name: &[u16],
            role: DirectoryOpenRole,
            case_insensitive: bool,
        ) -> Result<OwnedHandle, RootOpenError> {
            Self::nt_open_relative(
                parent,
                name,
                role.desired_access(),
                FILE_DIRECTORY_FILE,
                case_insensitive,
            )
        }

        fn open_child_entry(
            parent: &OwnedHandle,
            component: &[u16],
        ) -> Result<OwnedHandle, io::Error> {
            Self::nt_open_relative(
                parent.as_raw_handle() as HANDLE,
                component,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                0,
                false,
            )
            .map_err(|error| match error {
                RootOpenError::Io(error) => error,
                RootOpenError::NotDirectory => io::Error::new(
                    io::ErrorKind::InvalidData,
                    "child type changed during no-follow open",
                ),
                RootOpenError::Cancelled
                | RootOpenError::ReparsePoint
                | RootOpenError::UnsupportedNamespace => {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid child entry")
                }
            })
        }

        fn open_enumerated_child_directory(
            parent: &OwnedHandle,
            component: &[u16],
        ) -> Result<OwnedHandle, io::Error> {
            Self::nt_open_relative(
                parent.as_raw_handle() as HANDLE,
                component,
                DirectoryOpenRole::AdmittedRoot.desired_access(),
                FILE_DIRECTORY_FILE,
                false,
            )
            .map_err(|error| match error {
                RootOpenError::Io(error) => error,
                RootOpenError::NotDirectory => io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry changed during no-follow open",
                ),
                RootOpenError::Cancelled
                | RootOpenError::ReparsePoint
                | RootOpenError::UnsupportedNamespace => {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid child directory")
                }
            })
        }

        fn nt_open_relative(
            parent: HANDLE,
            name: &[u16],
            desired_access: u32,
            type_options: u32,
            case_insensitive: bool,
        ) -> Result<OwnedHandle, RootOpenError> {
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
                Attributes: if case_insensitive {
                    OBJ_CASE_INSENSITIVE
                } else {
                    0
                },
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
                    desired_access,
                    &object_attributes,
                    &mut io_status,
                    ptr::null(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN,
                    type_options
                        | FILE_OPEN_NO_RECALL
                        | FILE_OPEN_REPARSE_POINT
                        | FILE_SYNCHRONOUS_IO_NONALERT,
                    ptr::null(),
                    0,
                )
            };
            if status < 0 {
                return if matches!(
                    status,
                    STATUS_FILE_IS_A_DIRECTORY
                        | STATUS_NOT_A_DIRECTORY
                        | STATUS_OBJECT_TYPE_MISMATCH
                ) {
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
            let volume_role = if parsed.components.is_empty() {
                DirectoryOpenRole::AdmittedRoot
            } else {
                DirectoryOpenRole::Ancestor
            };
            let mut handle = Self::open_drive_volume_root(parsed.drive, volume_role)?;
            let mut observed = Self::reject_reparse_or_nondirectory(&handle)?;
            if cancel.is_cancelled() {
                return Err(RootOpenError::Cancelled);
            }
            let last_component = parsed.components.len().checked_sub(1);
            for (index, component) in parsed.components.into_iter().enumerate() {
                if cancel.is_cancelled() {
                    return Err(RootOpenError::Cancelled);
                }
                let role = if Some(index) == last_component {
                    DirectoryOpenRole::AdmittedRoot
                } else {
                    DirectoryOpenRole::Ancestor
                };
                let child = Self::open_child_directory(&handle, &component, role, true)?;
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
                reparse_tag: attributes.ReparseTag,
                standard,
                file_id,
            })
        }

        fn assert_directory_identity_current(
            directory: &WindowsDirectoryHandle,
        ) -> Result<(), PlatformError> {
            let observed = Self::query_metadata(&directory.handle)
                .map_err(|error| PlatformError::io(&directory.display_path, error))?;
            if Self::is_provider_boundary(observed.attributes)
                || observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || observed.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || !observed.standard.Directory
                || object_identity(&observed) != directory.identity
            {
                return Err(PlatformError::io(
                    &directory.display_path,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory identity or type changed after it was opened",
                    ),
                ));
            }
            Ok(())
        }

        fn parse_directory_query_record(
            directory_path: &Path,
            buffer: &[u8],
        ) -> Result<Option<EnumeratedChild>, io::Error> {
            let fixed_bytes = mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
            if buffer.len() < fixed_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NtQueryDirectoryFile returned an invalid record length",
                ));
            }
            let next_entry_offset = read_directory_query_field::<u32>(
                buffer,
                mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, NextEntryOffset),
                "NextEntryOffset",
            )?;
            let file_name_length = read_directory_query_field::<u32>(
                buffer,
                mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength),
                "FileNameLength",
            )?;
            let file_attributes = read_directory_query_field::<u32>(
                buffer,
                mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileAttributes),
                "FileAttributes",
            )?;
            let reparse_tag = read_directory_query_field::<u32>(
                buffer,
                mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, ReparsePointTag),
                "ReparsePointTag",
            )?;
            let file_id = read_directory_query_field::<[u8; 16]>(
                buffer,
                mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId),
                "FileId",
            )?;
            let (fixed_bytes, name_bytes) = validate_directory_query_lengths(
                buffer.len(),
                next_entry_offset,
                file_name_length,
            )?;
            let name_start = fixed_bytes;
            let name_end = name_start + name_bytes;
            let (name_units, remainder) = buffer[name_start..name_end].as_chunks::<2>();
            debug_assert!(remainder.is_empty());
            let name = name_units
                .iter()
                .map(|bytes| u16::from_ne_bytes(*bytes))
                .collect::<Vec<_>>();
            if name == [b'.' as u16] || name == [b'.' as u16, b'.' as u16] {
                return Ok(None);
            }
            let record = DirectoryEntryRecord::from_parent_and_name(
                directory_path,
                NativeName::windows_utf16(name),
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            Ok(Some(EnumeratedChild {
                record,
                identity: EnumeratedIdentity {
                    file_id,
                    is_directory: file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                    is_reparse: file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                    reparse_tag,
                },
            }))
        }

        fn query_next_directory_entry(
            directory: &mut WindowsDirectoryHandle,
            cancel: &CancellationToken,
        ) -> Result<Option<EnumeratedChild>, PlatformError> {
            loop {
                Self::ensure_not_cancelled(cancel)?;
                let DirectoryCursor::Active {
                    restart_scan,
                    pending,
                } = &mut directory.cursor
                else {
                    return Ok(None);
                };
                debug_assert!(pending.is_none());

                let mut buffer = vec![0u64; DIRECTORY_QUERY_BUFFER_BYTES / mem::size_of::<u64>()];
                let buffer_bytes = buffer.len() * mem::size_of::<u64>();
                let mut io_status = IO_STATUS_BLOCK::default();
                // SAFETY: the directory handle is live and has FILE_LIST_DIRECTORY access; the
                // output buffer and IO_STATUS_BLOCK remain writable for this synchronous call.
                // ReturnSingleEntry advances the cursor by at most one filesystem record.
                let status = unsafe {
                    NtQueryDirectoryFile(
                        directory.handle.as_raw_handle() as HANDLE,
                        ptr::null_mut(),
                        None,
                        ptr::null(),
                        &mut io_status,
                        buffer.as_mut_ptr().cast(),
                        u32::try_from(buffer_bytes).expect("directory query buffer fits u32"),
                        FileIdExtdDirectoryInformation,
                        true,
                        ptr::null(),
                        *restart_scan,
                    )
                };
                *restart_scan = false;
                let outcome = directory_query_outcome(
                    status,
                    io_status.Information,
                    buffer_bytes,
                    cancel,
                    &directory.display_path,
                )?;
                let DirectoryQueryOutcome::Record { bytes_returned } = outcome else {
                    directory.cursor = DirectoryCursor::Exhausted;
                    return Ok(None);
                };
                // SAFETY: the u64 allocation contains exactly buffer_bytes contiguous bytes and
                // remains live while the returned byte slice is inspected. The parser is called
                // only with this aligned allocation, as required by FILE_ID_EXTD_DIR_INFORMATION.
                let buffer_bytes = unsafe {
                    std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer_bytes)
                };
                if let Some(record) = Self::parse_directory_query_record(
                    &directory.display_path,
                    &buffer_bytes[..bytes_returned],
                )
                .map_err(|error| PlatformError::io(&directory.display_path, error))?
                {
                    Self::ensure_not_cancelled(cancel)?;
                    return Ok(Some(record));
                }
            }
        }

        fn expected_child_identity<'a>(
            parent: &'a WindowsDirectoryHandle,
            child: &DirectoryEntryRecord,
        ) -> Result<&'a EnumeratedIdentity, PlatformError> {
            let Some(expected) = parent
                .inspection_batch
                .iter()
                .find(|entry| entry.file_name == child.file_name)
                .map(|entry| &entry.identity)
            else {
                return Err(PlatformError::InvalidDirectoryEntry {
                    parent: parent.display_path.clone(),
                    detail: "child token was not returned by the most recent enumeration batch"
                        .to_string(),
                });
            };
            Ok(expected)
        }

        fn child_units(child: &DirectoryEntryRecord) -> Result<&[u16], PlatformError> {
            let NativeName::WindowsUtf16(units) = &child.file_name else {
                return Err(PlatformError::InvalidDirectoryEntry {
                    parent: child
                        .path
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .to_path_buf(),
                    detail: "Windows child name is not encoded as UTF-16".to_string(),
                });
            };
            child.file_name.validate_basename().map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: child
                        .path
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .to_path_buf(),
                    detail: error.to_string(),
                }
            })?;
            if Self::is_reserved_dos_device_name(units) {
                return Err(PlatformError::InvalidDirectoryEntry {
                    parent: child
                        .path
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .to_path_buf(),
                    detail: "Windows child name is a reserved DOS device alias".to_string(),
                });
            }
            Ok(units)
        }

        fn metadata_to_entry(
            path: &Path,
            file_name: NativeName,
            observed: &ObservedMetadata,
            kind: EntryKind,
        ) -> EntryMetadata {
            let logical_bytes = if kind == EntryKind::File {
                known_u128(observed.standard.EndOfFile.max(0) as u128)
            } else {
                known_u128(0)
            };
            let allocated_bytes = if kind == EntryKind::File {
                // FILE_STANDARD_INFO only covers the unnamed stream. Until all streams and their
                // allocation are enumerated, an exact filesystem allocation claim is unsafe.
                unknown_u128(ReasonCode::IncompleteStreamCoverage)
            } else {
                known_u128(0)
            };
            let identity = EntryIdentity::from_windows_file_id(
                observed.file_id.VolumeSerialNumber,
                observed.file_id.FileId.Identifier,
            );
            let fingerprint = fingerprint_for(Some(&identity), &kind, &logical_bytes);
            let hard_link_key =
                (kind == EntryKind::File).then(|| HardLinkKey::from(identity.clone()));

            EntryMetadata {
                path: path.to_path_buf(),
                file_name,
                kind,
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
                hard_link_key,
            }
        }

        fn valid_identity(observed: &ObservedMetadata) -> bool {
            observed.file_id.VolumeSerialNumber != 0
                && observed.file_id.FileId.Identifier != [0; 16]
        }

        fn is_provider_boundary(attributes: u32) -> bool {
            attributes
                & (FILE_ATTRIBUTE_OFFLINE
                    | FILE_ATTRIBUTE_RECALL_ON_OPEN
                    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                != 0
        }

        fn error_entry(path: &Path, error: io::Error) -> WalkEntry<WindowsDirectoryHandle> {
            WalkEntry::Error(ErrorRecord {
                path: path.to_path_buf(),
                kind: error_kind_for_io(&error),
                reason: reason_for_io(&error),
                detail: error.to_string(),
            })
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
                        "root must use an ordinary local drive-letter path without ambiguous Win32 components: {}",
                        root.path().display()
                    )),
                    RootOpenError::Io(error) => PlatformError::io(root.path(), error),
                })?;
            Self::ensure_not_cancelled(cancel)?;
            if !Self::valid_identity(&observed) {
                return Err(PlatformError::RootRejected(format!(
                    "root filesystem did not provide an authoritative volume and file identity: {}",
                    root.path().display()
                )));
            }
            if Self::is_provider_boundary(observed.attributes) {
                return Err(PlatformError::RootRejected(format!(
                    "root is offline or recall-on-access storage: {}",
                    root.path().display()
                )));
            }

            let metadata = Self::metadata_to_entry(
                root.path(),
                Self::native_name(root.path()),
                &observed,
                EntryKind::Directory,
            );
            let identity = object_identity(&observed);
            Ok(RootAdmission::new(
                root.clone(),
                metadata,
                WindowsDirectoryHandle {
                    handle,
                    display_path: root.path().to_path_buf(),
                    identity,
                    cursor: DirectoryCursor::NotStarted,
                    inspection_batch: Vec::new(),
                },
                root_locator,
            ))
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            Self::assert_directory_identity_current(directory)?;
            Self::ensure_not_cancelled(cancel)?;
            if limits.max_batch_entries == 0 || limits.max_batch_bytes == 0 {
                return Err(PlatformError::ResourceLimit(format!(
                    "directory batch limits must be nonzero at {}",
                    directory.display_path.display()
                )));
            }
            if matches!(directory.cursor, DirectoryCursor::Exhausted) {
                return Ok(DirectoryEntryBatch::complete(Vec::new()));
            }
            if matches!(directory.cursor, DirectoryCursor::NotStarted) {
                directory.cursor = DirectoryCursor::Active {
                    restart_scan: true,
                    pending: None,
                };
            }

            let mut entries = Vec::new();
            directory.inspection_batch.clear();
            let mut retained_bytes = 0usize;
            loop {
                Self::ensure_not_cancelled(cancel)?;
                let child = match &mut directory.cursor {
                    DirectoryCursor::Active { pending, .. } => match pending.take() {
                        Some(child) => Some(child),
                        None => Self::query_next_directory_entry(directory, cancel)?,
                    },
                    DirectoryCursor::Exhausted => None,
                    DirectoryCursor::NotStarted => {
                        unreachable!("directory cursor was initialized above")
                    }
                };
                let Some(child) = child else {
                    return Ok(DirectoryEntryBatch::complete(entries));
                };
                Self::ensure_not_cancelled(cancel)?;
                let DirectoryCursor::Active { pending, .. } = &mut directory.cursor else {
                    unreachable!("a yielded child requires an active cursor")
                };
                if let Some(batch) = take_bounded_entry(
                    pending,
                    &mut entries,
                    &mut directory.inspection_batch,
                    &mut retained_bytes,
                    child,
                    limits,
                    &directory.display_path,
                )? {
                    return Ok(batch);
                }
            }
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            child
                .validate_for_parent(&parent.display_path)
                .map_err(|error| PlatformError::InvalidDirectoryEntry {
                    parent: parent.display_path.clone(),
                    detail: error.to_string(),
                })?;
            Self::assert_directory_identity_current(parent)?;
            Self::ensure_not_cancelled(cancel)?;
            let units = Self::child_units(child)?;
            let expected = Self::expected_child_identity(parent, child)?;
            let handle = match Self::open_child_entry(&parent.handle, units) {
                Ok(handle) => handle,
                Err(error) => return Ok(Self::error_entry(&child.path, error)),
            };
            Self::ensure_not_cancelled(cancel)?;
            let observed = match Self::query_metadata(&handle) {
                Ok(observed) => observed,
                Err(error) => return Ok(Self::error_entry(&child.path, error)),
            };
            Self::ensure_not_cancelled(cancel)?;
            if !Self::valid_identity(&observed) {
                return Ok(Self::error_entry(
                    &child.path,
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "filesystem did not return an authoritative child identity",
                    ),
                ));
            }
            if let Err(error) =
                verify_enumerated_identity(parent.identity.volume, expected, &observed)
            {
                return Ok(Self::error_entry(&child.path, error));
            }

            if Self::is_provider_boundary(observed.attributes) {
                Self::ensure_not_cancelled(cancel)?;
                return Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: child.path.clone(),
                    kind: BoundaryKind::OtherFilesystem,
                    reason: ReasonCode::UnsupportedFilesystem,
                    detail: "offline or recall-on-access entry recorded without hydration"
                        .to_string(),
                }));
            }
            if observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                Self::ensure_not_cancelled(cancel)?;
                return Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: child.path.clone(),
                    kind: BoundaryKind::ReparsePoint,
                    reason: ReasonCode::UnsupportedFilesystem,
                    detail: format!(
                        "Windows reparse point 0x{:08x} recorded and not followed",
                        observed.reparse_tag
                    ),
                }));
            }
            if observed.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && observed.standard.Directory {
                let metadata = Self::metadata_to_entry(
                    &child.path,
                    child.file_name.clone(),
                    &observed,
                    EntryKind::Directory,
                );
                if directory_admission == DirectoryHandleAdmission::Deny {
                    return Ok(WalkEntry::Boundary(BoundaryRecord {
                        path: child.path.clone(),
                        kind: BoundaryKind::ResourceLimit,
                        reason: ReasonCode::ResourceLimit,
                        detail: "frontier limit exceeded".to_string(),
                    }));
                }
                Self::ensure_not_cancelled(cancel)?;
                let directory_handle =
                    match Self::open_enumerated_child_directory(&parent.handle, units) {
                        Ok(handle) => handle,
                        Err(error) => return Ok(Self::error_entry(&child.path, error)),
                    };
                Self::ensure_not_cancelled(cancel)?;
                let reopened = match Self::query_metadata(&directory_handle) {
                    Ok(observed) => observed,
                    Err(error) => return Ok(Self::error_entry(&child.path, error)),
                };
                Self::ensure_not_cancelled(cancel)?;
                if Self::is_provider_boundary(reopened.attributes) {
                    return Ok(WalkEntry::Boundary(BoundaryRecord {
                        path: child.path.clone(),
                        kind: BoundaryKind::OtherFilesystem,
                        reason: ReasonCode::UnsupportedFilesystem,
                        detail: "directory became offline or recall-on-access during inspection"
                            .to_string(),
                    }));
                }
                if !Self::valid_identity(&reopened) || !same_object(&observed, &reopened) {
                    return Ok(Self::error_entry(
                        &child.path,
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "directory identity changed between pinning and enumerable open",
                        ),
                    ));
                }
                Self::ensure_not_cancelled(cancel)?;
                return Ok(WalkEntry::Directory(OpenedDirectory {
                    metadata,
                    handle: WindowsDirectoryHandle {
                        handle: directory_handle,
                        display_path: child.path.clone(),
                        identity: object_identity(&reopened),
                        cursor: DirectoryCursor::NotStarted,
                        inspection_batch: Vec::new(),
                    },
                }));
            }
            if observed.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 || observed.standard.Directory {
                Self::ensure_not_cancelled(cancel)?;
                return Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: child.path.clone(),
                    kind: BoundaryKind::OtherFilesystem,
                    reason: ReasonCode::UnsupportedFilesystem,
                    detail: "directory metadata was inconsistent during inspection".to_string(),
                }));
            }
            Self::ensure_not_cancelled(cancel)?;
            Ok(WalkEntry::File(Self::metadata_to_entry(
                &child.path,
                child.file_name.clone(),
                &observed,
                EntryKind::File,
            )))
        }

        fn is_same_mount(
            &self,
            root: &EntryMetadata,
            entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            let root_mount = root.mount_identity.as_ref().ok_or_else(|| {
                PlatformError::Unsupported("root volume identity unavailable".to_string())
            })?;
            let entry_mount = entry.mount_identity.as_ref().ok_or_else(|| {
                PlatformError::Unsupported("entry volume identity unavailable".to_string())
            })?;
            let root_filesystem = root.filesystem_identity.as_ref().ok_or_else(|| {
                PlatformError::Unsupported(
                    "root filesystem object-domain identity unavailable".to_string(),
                )
            })?;
            let entry_filesystem = entry.filesystem_identity.as_ref().ok_or_else(|| {
                PlatformError::Unsupported(
                    "entry filesystem object-domain identity unavailable".to_string(),
                )
            })?;
            Ok(root_mount == entry_mount && root_filesystem == entry_filesystem)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        use sweepx_model::{EvidenceValue, NativeName};
        use windows_sys::Win32::Foundation::STATUS_ACCESS_DENIED;

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

        fn limits(max_entries: usize) -> DirectoryReadLimits {
            DirectoryReadLimits {
                max_batch_entries: max_entries,
                max_batch_bytes: 1024 * 1024,
            }
        }

        fn enumerated(record: DirectoryEntryRecord) -> EnumeratedChild {
            EnumeratedChild {
                record,
                identity: EnumeratedIdentity {
                    file_id: [1; 16],
                    is_directory: false,
                    is_reparse: false,
                    reparse_tag: 0,
                },
            }
        }

        fn collect_children(
            scanner: &WindowsPlatformScanner,
            directory: &mut WindowsDirectoryHandle,
            limits: DirectoryReadLimits,
        ) -> Vec<DirectoryEntryRecord> {
            let mut children = Vec::new();
            loop {
                let batch = scanner
                    .enumerate_children(directory, &CancellationToken::new(), limits)
                    .expect("directory enumeration succeeds");
                assert!(!batch.entries.is_empty() || batch.end_of_directory);
                children.extend(batch.entries);
                if batch.end_of_directory {
                    return children;
                }
            }
        }

        fn child_by_name(
            scanner: &WindowsPlatformScanner,
            directory: &mut WindowsDirectoryHandle,
            name: &str,
        ) -> DirectoryEntryRecord {
            let expected = name.encode_utf16().collect::<Vec<_>>();
            collect_children(scanner, directory, limits(32))
                .into_iter()
                .find(|child| {
                    matches!(&child.file_name, NativeName::WindowsUtf16(units) if units == &expected)
                })
                .unwrap_or_else(|| panic!("enumeration returned {name:?}"))
        }

        fn parse(path: &str) -> Result<ParsedDrivePath, RootOpenError> {
            WindowsPlatformScanner::parse_drive_path(Path::new(path))
        }

        #[test]
        fn parses_ordinary_components_without_changing_case() {
            let parsed =
                parse(r"c:\Mixed Case\.well-known\COM10").expect("ordinary Win32 components parse");

            assert_eq!(parsed.drive, b'C');
            assert_eq!(
                parsed.components,
                ["Mixed Case", ".well-known", "COM10"]
                    .map(|component| component.encode_utf16().collect::<Vec<_>>())
            );
        }

        #[test]
        fn rejects_trailing_dot_or_space_in_every_component() {
            for path in [
                r"C:\root.\child",
                r"C:\root \child",
                r"C:\root\child.",
                r"C:\root\child ",
                r"C:\root\...",
            ] {
                assert!(
                    matches!(parse(path), Err(RootOpenError::UnsupportedNamespace)),
                    "Win32-normalized component was accepted: {path:?}"
                );
            }
        }

        #[test]
        fn rejects_reserved_dos_device_names_case_insensitively() {
            for component in [
                "CON", "con", "PrN", "aux", "NUL", "CLOCK$", "clock$", "ConIn$", "conout$", "COM1",
                "com9", "LPT1", "lPt9", "COM¹", "com²", "LPT³",
            ] {
                let path = format!(r"C:\parent\{component}\child");
                assert!(
                    matches!(parse(&path), Err(RootOpenError::UnsupportedNamespace)),
                    "reserved DOS device name was accepted: {component:?}"
                );
            }
        }

        #[test]
        fn rejects_reserved_dos_device_aliases_with_extensions() {
            for component in [
                "NUL.txt",
                "nul.tar.gz",
                "CON .txt",
                "COM1.log",
                "lpt9...txt",
                "COM¹.data",
                "CLOCK$.log",
                "ConOut$.log",
            ] {
                let path = format!(r"C:\parent\{component}");
                assert!(
                    matches!(parse(&path), Err(RootOpenError::UnsupportedNamespace)),
                    "reserved DOS device alias was accepted: {component:?}"
                );
            }
        }

        #[test]
        fn accepts_near_miss_dos_device_names() {
            for component in [
                "CONSOLE", "NUL0", "COM0", "COM10", "COMA", "LPT0", "LPT10", "CONIN", "CONOUT",
                "XCLOCK$", "XCOM1", "COM1X",
            ] {
                let path = format!(r"C:\parent\{component}");
                assert!(
                    parse(&path).is_ok(),
                    "ordinary near-miss name was rejected: {component:?}"
                );
            }
        }

        #[test]
        fn ancestor_handles_do_not_request_enumeration_rights() {
            let ancestor = DirectoryOpenRole::Ancestor.desired_access();
            let admitted_root = DirectoryOpenRole::AdmittedRoot.desired_access();

            assert_eq!(ancestor & FILE_LIST_DIRECTORY, 0);
            assert_eq!(admitted_root & FILE_LIST_DIRECTORY, FILE_LIST_DIRECTORY);
            assert_eq!(ancestor, FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE);
            assert_eq!(admitted_root, ancestor | FILE_LIST_DIRECTORY);
        }

        #[test]
        fn metadata_mapping_preserves_full_file_id_and_conservative_sizes() {
            let mut observed = ObservedMetadata {
                attributes: 0,
                reparse_tag: 0,
                standard: FILE_STANDARD_INFO::default(),
                file_id: FILE_ID_INFO::default(),
            };
            observed.standard.EndOfFile = 987;
            observed.standard.AllocationSize = 1024;
            observed.standard.NumberOfLinks = 3;
            observed.file_id.VolumeSerialNumber = 42;
            observed.file_id.FileId.Identifier =
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

            let metadata = WindowsPlatformScanner::metadata_to_entry(
                Path::new(r"C:\root\file"),
                NativeName::windows_utf16("file".encode_utf16().collect::<Vec<_>>()),
                &observed,
                EntryKind::File,
            );

            let identity = metadata.identity.expect("file identity is present");
            assert_eq!(identity.device(), 42);
            assert_eq!(
                identity.windows_file_id(),
                observed.file_id.FileId.Identifier
            );
            assert_eq!(
                metadata
                    .hard_link_key
                    .as_ref()
                    .map(HardLinkKey::windows_file_id),
                Some(observed.file_id.FileId.Identifier)
            );
            assert!(matches!(
                metadata.logical_bytes,
                EvidenceValue::Known { value } if value.0 == 987
            ));
            assert!(matches!(
                metadata.allocated_bytes,
                EvidenceValue::Unknown {
                    reason: ReasonCode::IncompleteStreamCoverage
                }
            ));
            assert!(matches!(
                metadata.hard_link_count,
                EvidenceValue::Known { value } if value.0 == 3
            ));
        }

        #[test]
        fn enumerated_identity_rejects_replacement_type_and_tag_changes() {
            let mut observed = ObservedMetadata {
                attributes: 0,
                reparse_tag: 0,
                standard: FILE_STANDARD_INFO::default(),
                file_id: FILE_ID_INFO::default(),
            };
            observed.file_id.VolumeSerialNumber = 7;
            observed.file_id.FileId.Identifier = [3; 16];
            let expected = EnumeratedIdentity {
                file_id: [3; 16],
                is_directory: false,
                is_reparse: false,
                reparse_tag: 0,
            };
            assert!(verify_enumerated_identity(7, &expected, &observed).is_ok());

            observed.file_id.FileId.Identifier = [4; 16];
            assert!(verify_enumerated_identity(7, &expected, &observed).is_err());
            observed.file_id.FileId.Identifier = [3; 16];
            assert!(verify_enumerated_identity(8, &expected, &observed).is_err());
            observed.attributes = FILE_ATTRIBUTE_DIRECTORY;
            observed.standard.Directory = true;
            assert!(verify_enumerated_identity(7, &expected, &observed).is_err());

            observed.attributes = FILE_ATTRIBUTE_REPARSE_POINT;
            observed.standard.Directory = false;
            observed.reparse_tag = 0x1122_3344;
            let expected_reparse = EnumeratedIdentity {
                file_id: [3; 16],
                is_directory: false,
                is_reparse: true,
                reparse_tag: 0x5566_7788,
            };
            assert!(verify_enumerated_identity(7, &expected_reparse, &observed).is_err());
        }

        #[test]
        fn directory_reopen_comparison_rejects_provider_state_transition() {
            let mut before = ObservedMetadata {
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                reparse_tag: 0,
                standard: FILE_STANDARD_INFO::default(),
                file_id: FILE_ID_INFO::default(),
            };
            before.standard.Directory = true;
            before.file_id.VolumeSerialNumber = 7;
            before.file_id.FileId.Identifier = [3; 16];
            let mut after = ObservedMetadata {
                attributes: before.attributes,
                reparse_tag: before.reparse_tag,
                standard: before.standard,
                file_id: before.file_id,
            };

            assert!(same_object(&before, &after));
            after.attributes |= FILE_ATTRIBUTE_OFFLINE;
            assert!(WindowsPlatformScanner::is_provider_boundary(
                after.attributes
            ));
            assert!(!same_object(&before, &after));
        }

        fn directory_record_bytes(
            name: &[u16],
            next_entry_offset: u32,
            file_id: [u8; 16],
            attributes: u32,
            reparse_tag: u32,
        ) -> Vec<u64> {
            let fixed_bytes = mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
            let total_bytes = fixed_bytes + mem::size_of_val(name);
            let mut storage = vec![0u64; total_bytes.div_ceil(mem::size_of::<u64>())];
            let record = storage.as_mut_ptr().cast::<FILE_ID_EXTD_DIR_INFORMATION>();
            // SAFETY: the allocation is 8-byte aligned and large enough for the fixed header plus
            // every encoded UTF-16 name byte written below.
            unsafe {
                (*record).NextEntryOffset = next_entry_offset;
                (*record).FileNameLength = u32::try_from(name.len() * 2).unwrap();
                (*record).FileId.Identifier = file_id;
                (*record).FileAttributes = attributes;
                (*record).ReparsePointTag = reparse_tag;
                ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    (*record).FileName.as_mut_ptr(),
                    name.len(),
                );
            }
            storage
        }

        #[test]
        fn directory_query_record_parser_preserves_utf16_and_rejects_malformed_records() {
            let parent = Path::new(r"C:\root");
            let name = "MiXeD 🚀".encode_utf16().collect::<Vec<_>>();
            let storage = directory_record_bytes(
                &name,
                0,
                [9; 16],
                FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
                0xa000_000c,
            );
            // SAFETY: storage is initialized and viewed over exactly its owned byte extent.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    storage.as_ptr().cast::<u8>(),
                    storage.len() * mem::size_of::<u64>(),
                )
            };
            let child = WindowsPlatformScanner::parse_directory_query_record(parent, bytes)
                .expect("valid record parses")
                .expect("ordinary name is retained");
            assert_eq!(
                child.record.file_name,
                NativeName::windows_utf16(name.clone())
            );
            assert_eq!(child.identity.file_id, [9; 16]);
            assert!(child.identity.is_directory);
            assert!(child.identity.is_reparse);
            assert_eq!(child.identity.reparse_tag, 0xa000_000c);

            let dot_storage = directory_record_bytes(&[b'.' as u16], 0, [1; 16], 0, 0);
            let dot_bytes = unsafe {
                std::slice::from_raw_parts(
                    dot_storage.as_ptr().cast::<u8>(),
                    dot_storage.len() * mem::size_of::<u64>(),
                )
            };
            assert!(
                WindowsPlatformScanner::parse_directory_query_record(parent, dot_bytes)
                    .unwrap()
                    .is_none()
            );

            let continued = directory_record_bytes(&name, 8, [1; 16], 0, 0);
            let continued_bytes = unsafe {
                std::slice::from_raw_parts(
                    continued.as_ptr().cast::<u8>(),
                    continued.len() * mem::size_of::<u64>(),
                )
            };
            assert!(
                WindowsPlatformScanner::parse_directory_query_record(parent, continued_bytes)
                    .is_err()
            );
            assert!(
                WindowsPlatformScanner::parse_directory_query_record(parent, &bytes[..8]).is_err()
            );
        }

        #[test]
        fn bounded_entry_accounting_preserves_pending_cursor_state() {
            let path = Path::new(r"C:\root");
            let first = DirectoryEntryRecord::from_parent_and_name(
                path,
                NativeName::windows_utf16("first".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("first record is valid");
            let second = DirectoryEntryRecord::from_parent_and_name(
                path,
                NativeName::windows_utf16("second".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("second record is valid");
            let first_cost = first.estimated_retained_bytes().unwrap();
            let second_cost = second.estimated_retained_bytes().unwrap();
            let mut pending = None;
            let mut entries = Vec::new();
            let mut evidence = Vec::new();
            let mut retained_bytes = 0;
            let limits = DirectoryReadLimits {
                max_batch_entries: 1,
                max_batch_bytes: first_cost.max(second_cost),
            };

            assert!(
                take_bounded_entry(
                    &mut pending,
                    &mut entries,
                    &mut evidence,
                    &mut retained_bytes,
                    enumerated(first.clone()),
                    limits,
                    path,
                )
                .expect("first record fits")
                .is_none()
            );
            let page = take_bounded_entry(
                &mut pending,
                &mut entries,
                &mut evidence,
                &mut retained_bytes,
                enumerated(second.clone()),
                limits,
                path,
            )
            .expect("second record becomes pending")
            .expect("entry cap returns a page");
            assert_eq!(page.entries, vec![first]);
            assert!(!page.end_of_directory);
            assert_eq!(pending.as_ref().map(|child| &child.record), Some(&second));
            assert_eq!(evidence.len(), 1);
        }

        #[test]
        fn oversized_first_entry_remains_pending_after_resource_limit() {
            let path = Path::new(r"C:\root");
            let child = DirectoryEntryRecord::from_parent_and_name(
                path,
                NativeName::windows_utf16("large-child".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("child record is valid");
            let mut pending = None;
            let mut entries = Vec::new();
            let mut evidence = Vec::new();
            let mut retained_bytes = 0;

            assert!(matches!(
                take_bounded_entry(
                    &mut pending,
                    &mut entries,
                    &mut evidence,
                    &mut retained_bytes,
                    enumerated(child.clone()),
                    DirectoryReadLimits {
                        max_batch_entries: 1,
                        max_batch_bytes: 1,
                    },
                    path,
                ),
                Err(PlatformError::ResourceLimit(_))
            ));
            assert_eq!(pending.as_ref().map(|child| &child.record), Some(&child));
            assert!(entries.is_empty());
            assert!(evidence.is_empty());
            assert_eq!(retained_bytes, 0);
        }

        #[test]
        fn directory_query_length_validation_is_bounded() {
            let fixed = mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
            assert_eq!(
                validate_directory_query_lengths(fixed + 6, 0, 6).unwrap(),
                (fixed, 6)
            );
            assert!(validate_directory_query_lengths(fixed - 1, 0, 0).is_err());
            assert!(validate_directory_query_lengths(fixed + 6, 8, 6).is_err());
            assert!(validate_directory_query_lengths(fixed + 6, 0, 5).is_err());
            assert!(validate_directory_query_lengths(fixed + 4, 0, 6).is_err());
        }

        #[test]
        fn directory_query_parser_never_reads_past_fixed_header_boundary() {
            let fixed = mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileName);
            let mut header = vec![0u8; fixed];
            let name_length_offset = mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileNameLength);
            header[name_length_offset..name_length_offset + 4].copy_from_slice(&0u32.to_ne_bytes());

            assert!(
                WindowsPlatformScanner::parse_directory_query_record(
                    Path::new(r"C:\root"),
                    &header,
                )
                .is_err()
            );
            assert!(
                read_directory_query_field::<[u8; 16]>(
                    &header[..mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId) + 15],
                    mem::offset_of!(FILE_ID_EXTD_DIR_INFORMATION, FileId),
                    "FileId",
                )
                .is_err()
            );
        }

        #[test]
        fn cancellation_wins_over_every_directory_query_outcome() {
            let cancel = CancellationToken::new();
            cancel.cancel();
            let path = Path::new(r"C:\root");

            for (status, information) in [
                (STATUS_SUCCESS, 128),
                (STATUS_SUCCESS, 0),
                (STATUS_NO_MORE_FILES, 0),
                (STATUS_ACCESS_DENIED, 0),
                (STATUS_BUFFER_OVERFLOW, 0),
            ] {
                assert!(matches!(
                    directory_query_outcome(status, information, 1024, &cancel, path),
                    Err(PlatformError::Cancelled)
                ));
            }
        }

        #[test]
        fn same_volume_requires_both_identity_fields() {
            fn metadata(volume: Option<u64>, filesystem: Option<u64>) -> EntryMetadata {
                let kind = EntryKind::Directory;
                let logical_bytes = known_u128(0);
                EntryMetadata {
                    path: PathBuf::from(r"C:\root"),
                    file_name: NativeName::windows_utf16("root".encode_utf16().collect::<Vec<_>>()),
                    kind: kind.clone(),
                    logical_bytes: logical_bytes.clone(),
                    allocated_bytes: known_u128(0),
                    hard_link_count: known_count(1),
                    fingerprint: fingerprint_for(None, &kind, &logical_bytes),
                    identity: None,
                    filesystem_identity: filesystem.map(|device| FilesystemIdentity { device }),
                    mount_identity: volume.map(|value| MountIdentity { value }),
                    hard_link_key: None,
                }
            }

            let scanner = scanner();
            assert!(
                scanner
                    .is_same_mount(&metadata(Some(7), Some(7)), &metadata(Some(7), Some(7)))
                    .unwrap()
            );
            assert!(
                !scanner
                    .is_same_mount(&metadata(Some(7), Some(7)), &metadata(Some(8), Some(8)))
                    .unwrap()
            );
            assert!(matches!(
                scanner.is_same_mount(&metadata(Some(7), Some(7)), &metadata(None, Some(7))),
                Err(PlatformError::Unsupported(_))
            ));
            assert!(matches!(
                scanner.is_same_mount(&metadata(Some(7), Some(7)), &metadata(Some(7), None)),
                Err(PlatformError::Unsupported(_))
            ));
        }

        #[test]
        fn offline_and_recall_attributes_are_provider_boundaries() {
            for attributes in [
                FILE_ATTRIBUTE_OFFLINE,
                FILE_ATTRIBUTE_RECALL_ON_OPEN,
                FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
                FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
            ] {
                assert!(WindowsPlatformScanner::is_provider_boundary(attributes));
            }
            assert!(!WindowsPlatformScanner::is_provider_boundary(
                FILE_ATTRIBUTE_DIRECTORY
            ));
        }

        #[test]
        fn admission_rejects_ambiguous_win32_components_before_io() {
            for path in [
                r"C:\missing\child.",
                r"C:\missing\child ",
                r"C:\missing\NUL.txt",
                r"C:\missing\cOm1",
                r"C:\missing\LPT².log",
                r"C:\missing\CLOCK$",
                r"C:\missing\ConOut$.log",
            ] {
                let forged_root = ScanRoot {
                    path: PathBuf::from(path),
                };
                assert!(
                    matches!(
                        scanner().admit_root(&forged_root, &CancellationToken::new()),
                        Err(PlatformError::RootRejected(_))
                    ),
                    "ambiguous Win32 spelling reached filesystem I/O: {path:?}"
                );
            }
        }

        #[test]
        fn rejects_other_non_win32_component_spellings() {
            for path in [
                "C:\\parent\\control\u{1}",
                r#"C:\parent\quo"te"#,
                r"C:\parent\star*",
                r"C:\parent\question?",
                r"C:\parent\less<than",
                r"C:\parent\greater>than",
                r"C:\parent\pipe|",
            ] {
                assert!(
                    matches!(parse(path), Err(RootOpenError::UnsupportedNamespace)),
                    "non-Win32 component spelling was accepted: {path:?}"
                );
            }
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
        fn enumeration_remains_bound_to_renamed_directory_handle() {
            let container = TempDir::new("retained-enumeration");
            let original = container.0.join("root");
            let renamed = container.0.join("renamed");
            fs::create_dir(&original).expect("original directory is created");
            fs::write(original.join("retained-child"), b"old").expect("original child is created");
            let scanner = scanner();
            let mut admission = scanner
                .admit_root(
                    &ScanRoot::new(original.clone()).expect("root is absolute"),
                    &CancellationToken::new(),
                )
                .expect("original root is admitted");

            fs::rename(&original, &renamed).expect("admitted directory is renamed");
            fs::create_dir(&original).expect("replacement directory is created");
            fs::write(original.join("replacement-child"), b"new")
                .expect("replacement child is created");

            let names = collect_children(&scanner, &mut admission.directory, limits(16))
                .into_iter()
                .map(|entry| match entry.file_name {
                    NativeName::WindowsUtf16(units) => String::from_utf16(&units).unwrap(),
                    NativeName::UnixBytes(_) => unreachable!("Windows enumeration uses UTF-16"),
                })
                .collect::<std::collections::BTreeSet<_>>();
            assert!(names.contains("retained-child"));
            assert!(!names.contains("replacement-child"));
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
        fn enumerates_with_bounded_continuation_without_loss_or_duplicates() {
            let root = TempDir::new("bounded-enumeration");
            for name in ["alpha", "beta", "gamma", "delta", "epsilon"] {
                fs::write(root.0.join(name), name.as_bytes()).expect("test file is created");
            }
            let requested = ScanRoot::new(root.0.clone()).expect("root is absolute");
            let scanner = scanner();
            let mut admission = scanner
                .admit_root(&requested, &CancellationToken::new())
                .expect("ordinary directory is admitted");
            let entries = collect_children(&scanner, &mut admission.directory, limits(2));
            let names = entries
                .iter()
                .map(|entry| match &entry.file_name {
                    NativeName::WindowsUtf16(units) => String::from_utf16(units).unwrap(),
                    NativeName::UnixBytes(_) => unreachable!("Windows enumeration uses UTF-16"),
                })
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                names,
                ["alpha", "beta", "delta", "epsilon", "gamma"]
                    .map(String::from)
                    .into()
            );
            assert_eq!(entries.len(), names.len());

            assert!(matches!(
                scanner.enumerate_children(
                    &mut admission.directory,
                    &CancellationToken::new(),
                    DirectoryReadLimits {
                        max_batch_entries: 0,
                        max_batch_bytes: 1,
                    },
                ),
                Err(PlatformError::ResourceLimit(_))
            ));
        }

        #[test]
        fn enumerate_preserves_pending_entry_across_byte_limited_batches() {
            let root = TempDir::new("byte-limit");
            for name in ["alpha", "beta"] {
                fs::write(root.0.join(name), b"x").expect("test file is created");
            }
            let requested = ScanRoot::new(root.0.clone()).expect("root is absolute");
            let scanner = scanner();
            let mut admission = scanner
                .admit_root(&requested, &CancellationToken::new())
                .expect("ordinary directory is admitted");
            let first = scanner
                .enumerate_children(
                    &mut admission.directory,
                    &CancellationToken::new(),
                    limits(1),
                )
                .expect("first bounded page succeeds");
            assert_eq!(first.entries.len(), 1);
            assert!(!first.end_of_directory);
            let second = scanner
                .enumerate_children(
                    &mut admission.directory,
                    &CancellationToken::new(),
                    limits(1),
                )
                .expect("second bounded page succeeds");
            assert_eq!(second.entries.len(), 1);

            let mut too_small = scanner
                .admit_root(&requested, &CancellationToken::new())
                .expect("ordinary directory is admitted again");
            assert!(matches!(
                scanner.enumerate_children(
                    &mut too_small.directory,
                    &CancellationToken::new(),
                    DirectoryReadLimits {
                        max_batch_entries: 8,
                        max_batch_bytes: 1,
                    },
                ),
                Err(PlatformError::ResourceLimit(_))
            ));
            assert!(
                !scanner
                    .enumerate_children(
                        &mut too_small.directory,
                        &CancellationToken::new(),
                        limits(8),
                    )
                    .expect("pending entry remains available")
                    .entries
                    .is_empty()
            );
        }

        #[test]
        fn inspects_file_and_directory_relative_to_retained_parent() {
            let root = TempDir::new("inspect");
            fs::write(root.0.join("file"), b"hello world").expect("file is created");
            fs::hard_link(root.0.join("file"), root.0.join("second"))
                .expect("hard link is created");
            fs::create_dir(root.0.join("directory")).expect("directory is created");
            let scanner = scanner();
            let mut admission = scanner
                .admit_root(
                    &ScanRoot::new(root.0.clone()).expect("root is absolute"),
                    &CancellationToken::new(),
                )
                .expect("root is admitted");
            let file = child_by_name(&scanner, &mut admission.directory, "file");
            let second = DirectoryEntryRecord::from_parent_and_name(
                &root.0,
                NativeName::windows_utf16("second".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("second child record is valid");
            let directory = DirectoryEntryRecord::from_parent_and_name(
                &root.0,
                NativeName::windows_utf16("directory".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("directory child record is valid");

            let WalkEntry::File(file_metadata) = scanner
                .inspect_child(&admission.directory, &file, &CancellationToken::new())
                .expect("file inspection succeeds")
            else {
                panic!("expected file metadata");
            };
            let WalkEntry::File(second_metadata) = scanner
                .inspect_child(&admission.directory, &second, &CancellationToken::new())
                .expect("hard-link inspection succeeds")
            else {
                panic!("expected hard-link metadata");
            };
            assert_eq!(file_metadata.identity, second_metadata.identity);
            assert_eq!(file_metadata.hard_link_key, second_metadata.hard_link_key);
            assert!(matches!(
                file_metadata.logical_bytes,
                EvidenceValue::Known { value } if value.0 == 11
            ));
            assert!(matches!(
                file_metadata.allocated_bytes,
                EvidenceValue::Unknown {
                    reason: ReasonCode::IncompleteStreamCoverage
                }
            ));

            let WalkEntry::Directory(opened) = scanner
                .inspect_child(&admission.directory, &directory, &CancellationToken::new())
                .expect("directory inspection succeeds")
            else {
                panic!("expected opened directory");
            };
            assert!(matches!(
                scanner.is_same_mount(&admission.metadata, &opened.metadata),
                Ok(true)
            ));
        }

        #[test]
        fn inspect_child_rejects_forged_record_and_does_not_reopen_display_path() {
            let root = TempDir::new("forged-child");
            fs::write(root.0.join("actual"), b"x").expect("test file is created");
            let scanner = scanner();
            let admission = scanner
                .admit_root(
                    &ScanRoot::new(root.0.clone()).expect("root is absolute"),
                    &CancellationToken::new(),
                )
                .expect("root is admitted");
            let forged = DirectoryEntryRecord {
                path: root.0.join("different"),
                file_name: NativeName::windows_utf16("actual".encode_utf16().collect::<Vec<_>>()),
            };
            assert!(matches!(
                scanner.inspect_child(&admission.directory, &forged, &CancellationToken::new()),
                Err(PlatformError::InvalidDirectoryEntry { .. })
            ));
        }

        #[test]
        fn inspect_missing_child_is_a_walk_error() {
            let root = TempDir::new("missing-child");
            let scanner = scanner();
            let admission = scanner
                .admit_root(
                    &ScanRoot::new(root.0.clone()).expect("root is absolute"),
                    &CancellationToken::new(),
                )
                .expect("root is admitted");
            let missing = DirectoryEntryRecord::from_parent_and_name(
                &root.0,
                NativeName::windows_utf16("missing".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("missing child record is valid");

            assert!(matches!(
                scanner
                    .inspect_child(&admission.directory, &missing, &CancellationToken::new())
                    .expect("missing child is represented in-band"),
                WalkEntry::Error(_)
            ));
        }

        #[test]
        fn child_open_is_case_exact_to_the_enumerated_token() {
            let root = TempDir::new("case-exact-child");
            fs::write(root.0.join("MixedCase"), b"x").expect("test file is created");
            let scanner = scanner();
            let admission = scanner
                .admit_root(
                    &ScanRoot::new(root.0.clone()).expect("root is absolute"),
                    &CancellationToken::new(),
                )
                .expect("root is admitted");
            let wrong_case = DirectoryEntryRecord::from_parent_and_name(
                &root.0,
                NativeName::windows_utf16("mixedcase".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("case-variant record is valid");

            assert!(matches!(
                scanner
                    .inspect_child(&admission.directory, &wrong_case, &CancellationToken::new())
                    .expect("case mismatch is represented in-band"),
                WalkEntry::Error(_)
            ));
        }

        #[test]
        fn reparse_child_is_a_boundary_and_is_not_followed_when_creation_is_permitted() {
            let root = TempDir::new("child-reparse");
            let target = root.0.join("target");
            let link = root.0.join("link");
            fs::create_dir(&target).expect("target directory is created");
            match std::os::windows::fs::symlink_dir(&target, &link) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
                Err(error) => panic!("directory symlink creation failed: {error}"),
            }
            let scanner = scanner();
            let mut admission = scanner
                .admit_root(
                    &ScanRoot::new(root.0.clone()).expect("root is absolute"),
                    &CancellationToken::new(),
                )
                .expect("root is admitted");
            let child = child_by_name(&scanner, &mut admission.directory, "link");
            assert!(matches!(
                scanner
                    .inspect_child(&admission.directory, &child, &CancellationToken::new())
                    .expect("reparse inspection succeeds"),
                WalkEntry::Boundary(BoundaryRecord {
                    kind: BoundaryKind::ReparsePoint,
                    ..
                })
            ));
        }

        #[test]
        fn cancellation_precedes_enumeration_and_inspection() {
            let root = TempDir::new("child-cancel");
            fs::write(root.0.join("file"), b"x").expect("test file is created");
            let scanner = scanner();
            let mut admission = scanner
                .admit_root(
                    &ScanRoot::new(root.0.clone()).expect("root is absolute"),
                    &CancellationToken::new(),
                )
                .expect("root is admitted");
            let child = DirectoryEntryRecord::from_parent_and_name(
                &root.0,
                NativeName::windows_utf16("file".encode_utf16().collect::<Vec<_>>()),
            )
            .expect("child record is valid");
            let forged = DirectoryEntryRecord {
                path: root.0.join("different"),
                file_name: child.file_name.clone(),
            };
            let cancel = CancellationToken::new();
            cancel.cancel();

            assert!(matches!(
                scanner.enumerate_children(&mut admission.directory, &cancel, limits(8)),
                Err(PlatformError::Cancelled)
            ));
            assert!(matches!(
                scanner.inspect_child(&admission.directory, &child, &cancel),
                Err(PlatformError::Cancelled)
            ));
            assert!(matches!(
                scanner.inspect_child(&admission.directory, &forged, &cancel),
                Err(PlatformError::Cancelled)
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

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            _directory_admission: sweepx_platform::DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inspect_child(parent, child, cancel)
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
