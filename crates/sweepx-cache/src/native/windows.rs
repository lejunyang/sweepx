//! Windows cache I/O uses relative NT opens, retained handles and protected private DACLs.
//! No operation reconstructs a pathname after admission. Unsupported namespaces are cache misses.

use super::{EntryMetadata, write_json};
use crate::windows_state_security::{PrivateSecurityDescriptor, is_private_owned_handle};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, Prefix};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_NO_RECALL, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT, FileDispositionInformation, FileFsDeviceInformation,
    FileNamesInformation, FileRenameInformation, NtCreateFile, NtQueryDirectoryFile,
    NtQueryVolumeInformationFile, NtSetInformationFile,
};
use windows_sys::Wdk::System::SystemServices::{
    FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOTE_DEVICE_VSMB,
};
use windows_sys::Win32::Foundation::{
    FILETIME, HANDLE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError, STATUS_NO_MORE_FILES,
    UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_DEVICE_DISK,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FileBasicInfo,
    FileIdInfo, FileStandardInfo, GetDriveTypeW, GetFileInformationByHandleEx, GetFileType,
    READ_CONTROL, ReOpenFile, SYNCHRONIZE, SetFileTime,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Ioctl::FILE_DEVICE_DISK_FILE_SYSTEM;
use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE};

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const DIR_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL;
const REFUSED: u32 = FILE_ATTRIBUTE_REPARSE_POINT
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

/// A private cache directory retained by native handle; display paths are not reopened.
pub struct Directory {
    file: File,
    volume: u64,
}

/// A non-inheritable, share-none lock file. Closing the handle releases publication exclusion;
/// readers need no lock and deny data-write/delete sharing while reading an existing generation.
/// Releases this invocation's cache publication exclusion when dropped.
pub struct LockGuard {
    _file: File,
}

impl Directory {
    /// Opens an absolute no-follow cache root, optionally creating private components.
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        // Bound the complete request before walking or allocating individual components.
        crate::windows_state_policy::terminated_utf16(path.as_os_str().encode_wide())
            .ok_or_else(|| io::Error::other("cache path exceeds native admission bounds"))?;
        let mut parts = path.components();
        let drive = match parts.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive)
                    if drive.is_ascii_alphabetic() =>
                {
                    drive.to_ascii_uppercase()
                }
                _ => return Err(io::Error::other("unsupported cache namespace")),
            },
            _ => {
                return Err(io::Error::other(
                    "cache path must have an absolute drive root",
                ));
            }
        };
        if !matches!(parts.next(), Some(Component::RootDir)) {
            return Err(io::Error::other("cache path must be absolute"));
        }
        let root = [u16::from(drive), b':' as u16, b'\\' as u16, 0];
        // Reject mapped network drives as well as explicit UNC/device namespaces. Native calls
        // on remote providers have no scan-cancellation/deadline contract in this cache backend.
        if !matches!(
            unsafe { GetDriveTypeW(root.as_ptr()) },
            DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_RAMDISK
        ) {
            return Err(io::Error::other(
                "cache drive is not a supported local disk",
            ));
        }
        let name: Vec<u16> = format!("\\??\\{}:\\", char::from(drive))
            .encode_utf16()
            .collect();
        let file = open_native(
            ptr::null_mut(),
            &name,
            DIR_ACCESS,
            FILE_DIRECTORY_FILE,
            FILE_OPEN,
            SHARE_ALL,
            None,
        )?;
        let volume = ordinary(&file, true, None)?.VolumeSerialNumber;
        let mut current = Self { file, volume };
        let descriptor = if create {
            Some(PrivateSecurityDescriptor::new()?)
        } else {
            None
        };
        for part in parts {
            let Component::Normal(part) = part else {
                if matches!(part, Component::CurDir) {
                    continue;
                }
                return Err(io::Error::other("invalid cache path component"));
            };
            let name = component(part)?;
            let next = match current.open_relative(
                &name,
                DIR_ACCESS,
                FILE_DIRECTORY_FILE,
                FILE_OPEN,
                SHARE_ALL,
                None,
            ) {
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => current
                    .open_relative(
                        &name,
                        DIR_ACCESS,
                        FILE_DIRECTORY_FILE,
                        FILE_OPEN_IF,
                        SHARE_ALL,
                        descriptor.as_ref(),
                    )?,
                result => result?,
            };
            ordinary(&next, true, Some(volume))?;
            current.file = next;
        }
        current.private()?;
        Ok(current)
    }

    fn private(&self) -> io::Result<()> {
        ordinary(&self.file, true, Some(self.volume))?;
        private(&self.file)
    }

    fn open_relative(
        &self,
        name: &[u16],
        access: u32,
        kind: u32,
        disposition: u32,
        share: u32,
        descriptor: Option<&PrivateSecurityDescriptor>,
    ) -> io::Result<File> {
        open_native(
            self.file.as_raw_handle().cast(),
            name,
            access,
            kind,
            disposition,
            share,
            descriptor,
        )
    }

    /// Opens a private child directory relative to this retained handle.
    pub fn child(&self, name: &str) -> io::Result<Self> {
        self.private()?;
        let file = self.open_relative(
            &component(OsStr::new(name))?,
            DIR_ACCESS,
            FILE_DIRECTORY_FILE,
            FILE_OPEN,
            SHARE_ALL,
            None,
        )?;
        ordinary(&file, true, Some(self.volume))?;
        private(&file)?;
        Ok(Self {
            file,
            volume: self.volume,
        })
    }

    /// Creates or admits a private child beneath this retained directory.
    pub fn create_child(&self, name: &str) -> io::Result<Self> {
        self.private()?;
        let descriptor = PrivateSecurityDescriptor::new()?;
        let file = self.open_relative(
            &component(OsStr::new(name))?,
            DIR_ACCESS,
            FILE_DIRECTORY_FILE,
            FILE_OPEN_IF,
            SHARE_ALL,
            Some(&descriptor),
        )?;
        ordinary(&file, true, Some(self.volume))?;
        let child = Self {
            file,
            volume: self.volume,
        };
        child.private()?;
        Ok(child)
    }

    /// Nonblocking publication exclusion; contention makes the cache unavailable.
    pub fn lock(&self) -> io::Result<LockGuard> {
        self.private()?;
        let descriptor = PrivateSecurityDescriptor::new()?;
        // Share-none makes contention fail synchronously; never truncate or replace a lock file.
        let file = self.open_relative(
            &component(OsStr::new(".lock"))?,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_NON_DIRECTORY_FILE,
            FILE_OPEN_IF,
            0,
            Some(&descriptor),
        )?;
        self.valid_file(&file)?;
        Ok(LockGuard { _file: file })
    }

    pub(super) fn open_file(&self, name: &str) -> io::Result<File> {
        self.private()?;
        let file = self.open_relative(
            &component(OsStr::new(name))?,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL,
            FILE_NON_DIRECTORY_FILE,
            FILE_OPEN,
            FILE_SHARE_READ,
            None,
        )?;
        self.valid_file(&file)?;
        Ok(file)
    }

    fn valid_file(&self, file: &File) -> io::Result<()> {
        ordinary(file, false, Some(self.volume))?;
        revalidate_file(file)
    }

    /// Atomically publishes bounded JSON; this disposable cache write is not crash durable.
    pub fn write_json(
        &self,
        name: &str,
        value: &impl serde::Serialize,
        cap: usize,
    ) -> io::Result<()> {
        self.publish(name, |file| write_json(file, value, cap))
    }

    /// Runs the encoder on an exclusively created private temporary, then publishes it
    /// beneath the same retained parent. Failure removes only this invocation's temporary.
    pub(crate) fn publish(
        &self,
        name: &str,
        encode: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<()> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        self.private()?;
        match self.open_file(name) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let destination = component(OsStr::new(name))?;
        let temp = component(OsStr::new(&format!(
            ".sweepx-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))?;
        let descriptor = PrivateSecurityDescriptor::new()?;
        let mut file = self.open_relative(
            &temp,
            FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE,
            FILE_NON_DIRECTORY_FILE,
            FILE_CREATE,
            0,
            Some(&descriptor),
        )?;
        let result = (|| {
            self.valid_file(&file)?;
            encode(&mut file)?;
            self.private()?;
            self.valid_file(&file)?;
            rename(&file, &self.file, &destination)
        })();
        if result.is_err() {
            // Delete only the handle returned by our exclusive FILE_CREATE, even after a rename
            // of an ancestor. Cleanup failure leaves a managed temporary for later eviction.
            let _ = dispose(&file);
        }
        result
    }

    /// Removes a managed cache basename without following its target.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        self.private()?;
        let file = self.open_relative(
            &component(OsStr::new(name))?,
            DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_NON_DIRECTORY_FILE,
            FILE_OPEN,
            FILE_SHARE_READ,
            None,
        )?;
        self.valid_file(&file)?;
        // This removes a managed cache object, never a scanned payload or linked target.
        dispose(&file)
    }

    /// Reads native encoded length and LRU time for a managed cache basename.
    pub fn metadata(&self, name: &str) -> io::Result<EntryMetadata> {
        let file = self.open_file(name)?;
        let basic: FILE_BASIC_INFO = query(&file, FileBasicInfo)?;
        let standard: FILE_STANDARD_INFO = query(&file, FileStandardInfo)?;
        Ok(EntryMetadata {
            bytes: u64::try_from(standard.EndOfFile).map_err(io::Error::other)?,
            // Raw Windows ticks suffice for ordering; no fabricated Unix epoch conversion.
            accessed: (basic.LastAccessTime, 0),
        })
    }

    /// Visits managed UTF-8 names within a fixed native enumeration budget.
    pub fn entries(&self, mut visit: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        self.entries_all(|name| match name {
            Some(".lock") | None => Ok(()),
            Some(name) => visit(name),
        })
    }

    pub(crate) fn entries_all(
        &self,
        mut visit: impl FnMut(Option<&str>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.private()?;
        // ReOpenFile creates an independent cursor on the same retained object. A duplicate
        // handle would share the cursor, and reopening a display path could reach a replacement.
        let original: FILE_ID_INFO = query(&self.file, FileIdInfo)?;
        // SAFETY: the handle is live and the flags request an ordinary synchronous directory
        // handle. Reparse/provider attributes and native identity are checked before enumeration.
        let raw = unsafe {
            ReOpenFile(
                self.file.as_raw_handle().cast(),
                DIR_ACCESS | SYNCHRONIZE,
                SHARE_ALL,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let directory = unsafe { File::from_raw_handle(raw.cast()) };
        let reopened: FILE_ID_INFO = query(&directory, FileIdInfo)?;
        if reopened.VolumeSerialNumber != original.VolumeSerialNumber
            || reopened.FileId.Identifier != original.FileId.Identifier
        {
            return Err(io::Error::other(
                "cache enumeration reopened another identity",
            ));
        }
        ordinary(&directory, true, Some(self.volume))?;
        let mut page = vec![0usize; (64 * 1024) / size_of::<usize>()];
        let mut remaining = super::ENUMERATION_ENTRY_LIMIT;
        // One extra query allows the terminal NO_MORE_FILES status at the entry cap. Zero-byte
        // success/overflow/unknown status is a miss, not permission to grow or loop indefinitely.
        for _ in 0..=super::ENUMERATION_ENTRY_LIMIT {
            let mut status_block = IO_STATUS_BLOCK::default();
            // SAFETY: live synchronous directory, pointer-aligned 64 KiB output allocation;
            // no event/APC is supplied, and no native pointer outlives the allocation.
            let status = unsafe {
                NtQueryDirectoryFile(
                    directory.as_raw_handle().cast(),
                    ptr::null_mut(),
                    None,
                    ptr::null(),
                    &mut status_block,
                    page.as_mut_ptr().cast(),
                    64 * 1024,
                    FileNamesInformation,
                    false,
                    ptr::null(),
                    false,
                )
            };
            if status == STATUS_NO_MORE_FILES {
                return Ok(());
            }
            nt_result(status)?;
            let length = status_block.Information;
            if length == 0 || length > 64 * 1024 {
                return Err(io::Error::other("invalid cache enumeration completion"));
            }
            // SAFETY: the successful native call reported initialized bytes within this buffer.
            let bytes = unsafe { std::slice::from_raw_parts(page.as_ptr().cast::<u8>(), length) };
            super::windows_names::visit_names_all(bytes, &mut remaining, |name| {
                if matches!(name, Some("." | "..")) {
                    return Ok(());
                }
                visit(name)
            })?;
        }
        Err(io::Error::other("cache enumeration query budget exceeded"))
    }
}

fn component(name: &OsStr) -> io::Result<Vec<u16>> {
    let mut units = Vec::with_capacity(32);
    for unit in name.encode_wide() {
        if units.len() == 255 || matches!(unit, 0 | 47 | 92 | 58) {
            return Err(io::Error::other("invalid or oversized cache basename"));
        }
        units.push(unit);
    }
    if units.is_empty() || units == [46] || units == [46, 46] {
        return Err(io::Error::other("invalid cache basename"));
    }
    Ok(units)
}

#[allow(clippy::too_many_arguments)]
fn open_native(
    parent: HANDLE,
    name: &[u16],
    access: u32,
    kind: u32,
    disposition: u32,
    share: u32,
    descriptor: Option<&PrivateSecurityDescriptor>,
) -> io::Result<File> {
    let length = u16::try_from(
        name.len()
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("oversized cache name"))?,
    )
    .map_err(io::Error::other)?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &name,
        Attributes: 0,
        SecurityDescriptor: descriptor.map_or(ptr::null(), |value| value.as_ptr().cast()),
        SecurityQualityOfService: ptr::null(),
    };
    let mut file = ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the parent is either the initial drive namespace or a live retained directory;
    // all counted input and output structures remain live throughout this synchronous call.
    let status = unsafe {
        NtCreateFile(
            &mut file,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            ptr::null(),
            0,
            share,
            disposition,
            // NTFS refuses DIRECTORY_FILE + NO_RECALL (the native scanner observes the same
            // restriction). Directories have no data stream; their online/reparse attributes
            // are checked before enumeration. Every file open still requests NO_RECALL.
            kind | FILE_OPEN_REPARSE_POINT
                | if kind & FILE_DIRECTORY_FILE == 0 {
                    FILE_OPEN_NO_RECALL
                } else {
                    0
                }
                | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        nt_result(status)?;
    }
    if file.is_null() || file == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("Windows returned no cache handle"));
    }
    // SAFETY: successful NtCreateFile returns a fresh, non-inheritable handle, transferred once.
    let file = unsafe { File::from_raw_handle(file.cast()) };
    // NT_SUCCESS can include informational statuses. Own the returned handle before refusing
    // an unexpected positive completion, so conservative cache failure cannot leak it.
    nt_result(status)?;
    Ok(file)
}

fn nt_result(status: i32) -> io::Result<()> {
    if status == 0 {
        return Ok(());
    }
    if status >= 0 {
        return Err(io::Error::other("unexpected asynchronous cache completion"));
    }
    // SAFETY: converts an integer status without borrowing native memory.
    Err(io::Error::from_raw_os_error(
        unsafe { RtlNtStatusToDosError(status) } as i32,
    ))
}

fn query<T>(file: &File, class: i32) -> io::Result<T> {
    let mut result = MaybeUninit::<T>::uninit();
    // SAFETY: every caller pairs the SDK information class with its exact native type and size;
    // success initializes the entire structure in its naturally aligned allocation.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            class,
            result.as_mut_ptr().cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { result.assume_init() })
}

fn ordinary(file: &File, directory: bool, volume: Option<u64>) -> io::Result<FILE_ID_INFO> {
    let mut device = MaybeUninit::<FILE_FS_DEVICE_INFORMATION>::uninit();
    let mut completion = IO_STATUS_BLOCK::default();
    // SAFETY: exact SDK class/type, naturally aligned fixed output and a live synchronous handle.
    // Checking the opened device closes the drive-alias race in the earlier pathname precheck.
    nt_result(unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle().cast(),
            &mut completion,
            device.as_mut_ptr().cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    })?;
    if completion.Information != size_of::<FILE_FS_DEVICE_INFORMATION>() {
        return Err(io::Error::other("incomplete cache device information"));
    }
    let device = unsafe { device.assume_init() };
    if !matches!(
        device.DeviceType,
        FILE_DEVICE_DISK | FILE_DEVICE_DISK_FILE_SYSTEM
    ) || device.Characteristics & (FILE_REMOTE_DEVICE | FILE_REMOTE_DEVICE_VSMB) != 0
    {
        return Err(io::Error::other("cache object belongs to a remote device"));
    }
    let metadata = file.metadata()?;
    let standard: FILE_STANDARD_INFO = query(file, FileStandardInfo)?;
    let id: FILE_ID_INFO = query(file, FileIdInfo)?;
    // SAFETY: GetFileType observes the live handle and has no borrowed output.
    if unsafe { GetFileType(file.as_raw_handle().cast()) } != FILE_TYPE_DISK
        || metadata.file_attributes() & REFUSED != 0
        || metadata.is_dir() != directory
        || standard.Directory != directory
        || standard.DeletePending
        || standard.EndOfFile < 0
        || volume.is_some_and(|expected| expected != id.VolumeSerialNumber)
    {
        return Err(io::Error::other(
            "cache object is not ordinary online storage in its admitted volume",
        ));
    }
    Ok(id)
}

fn private(file: &File) -> io::Result<()> {
    if !is_private_owned_handle(file)? {
        return Err(io::Error::other("cache object is not current-user private"));
    }
    Ok(())
}

pub(super) fn revalidate_file(file: &File) -> io::Result<()> {
    ordinary(file, false, None)?;
    let standard: FILE_STANDARD_INFO = query(file, FileStandardInfo)?;
    if standard.NumberOfLinks != 1 {
        return Err(io::Error::other("cache file must have exactly one link"));
    }
    private(file)
}

pub(super) fn same_observation(left: &Metadata, right: &Metadata) -> bool {
    // The same handle is retained and data-write/delete sharing is denied. Access time is LRU
    // only. Revalidation separately checks current privacy, type, provider attributes and links.
    left.file_size() == right.file_size()
        && left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_attributes() == right.file_attributes()
}

pub(super) fn touch_accessed(file: &File) {
    // Windows FILETIME is 100 ns ticks since 1601. Only cache LRU uses this timestamp; it never
    // validates scan facts. Failure to touch does not change the already admitted history.
    let Some(ticks) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_nanos().checked_div(100))
        .and_then(|ticks| ticks.checked_add(116_444_736_000_000_000))
        .and_then(|ticks| u64::try_from(ticks).ok())
    else {
        return;
    };
    let time = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    // SAFETY: live WRITE_ATTRIBUTES handle and one initialized timestamp; other times unchanged.
    unsafe { SetFileTime(file.as_raw_handle().cast(), ptr::null(), &time, ptr::null()) };
}

fn rename(file: &File, parent: &File, name: &[u16]) -> io::Result<()> {
    let name_bytes = name.len() * 2; // component admission already bounds this to 510 bytes.
    let offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let length = size_of::<FILE_RENAME_INFORMATION>().max(offset + name_bytes);
    let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
    let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: pointer-aligned, zero-initialized variable SDK structure, large enough for header
    // and the complete counted name. Target is relative to the live admitted directory handle.
    unsafe {
        (*rename).Anonymous.ReplaceIfExists = true;
        (*rename).RootDirectory = parent.as_raw_handle().cast();
        (*rename).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
            name.len(),
        );
    }
    let mut status = IO_STATUS_BLOCK::default();
    nt_result(unsafe {
        NtSetInformationFile(
            file.as_raw_handle().cast(),
            &mut status,
            rename.cast(),
            length as u32,
            FileRenameInformation,
        )
    })
}

fn dispose(file: &File) -> io::Result<()> {
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: live DELETE handle and correctly sized, initialized SDK disposition structure.
    nt_result(unsafe {
        NtSetInformationFile(
            file.as_raw_handle().cast(),
            &mut status,
            (&disposition as *const FILE_DISPOSITION_INFORMATION).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::super::{Limits, ReadBudget};
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl};

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Directory) {
        let guard = tempfile::tempdir().unwrap();
        let path = guard.path().join("cache");
        let directory = Directory::open(&path, true).unwrap();
        (guard, path, directory)
    }

    #[test]
    fn retained_parent_lock_and_enumeration_survive_path_replacement() {
        let (guard, path, directory) = fixture();
        let mut lower_drive: Vec<_> = path.as_os_str().encode_wide().collect();
        lower_drive[0] = u16::from((lower_drive[0] as u8).to_ascii_lowercase());
        assert!(
            Directory::open(
                Path::new(&std::ffi::OsString::from_wide(&lower_drive)),
                false
            )
            .is_ok()
        );
        assert_eq!(
            offset_of!(
                windows_sys::Wdk::Storage::FileSystem::FILE_NAMES_INFORMATION,
                FileName
            ),
            12
        );
        let lock = directory.lock().unwrap();
        assert!(
            directory.lock().is_err(),
            "share-none must claim actual data access"
        );
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(lock._file.as_raw_handle().cast(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        drop(lock);
        assert!(directory.lock().is_ok());
        let retained = guard.path().join("retained");
        fs::rename(&path, &retained).unwrap();
        let replacement = Directory::open(&path, true).unwrap();
        replacement
            .write_json("other", &"replacement", 128)
            .unwrap();
        directory.write_json("fact", &"retained", 128).unwrap();
        assert_eq!(fs::read(retained.join("fact")).unwrap(), br#""retained""#);
        assert!(!path.join("fact").exists());
        let expected: BTreeSet<_> = fs::read_dir(&retained)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != ".lock")
            .collect();
        for _ in 0..2 {
            let mut actual = BTreeSet::new();
            directory
                .entries(|name| {
                    actual.insert(name.to_owned());
                    Ok(())
                })
                .unwrap();
            assert_eq!(actual, expected);
        }
        directory.remove("fact").unwrap();
        assert!(!retained.join("fact").exists());
        assert_eq!(fs::read(path.join("other")).unwrap(), br#""replacement""#);
    }

    #[test]
    fn bounded_input_atomic_publication_and_read_sharing_preserve_old_generation() {
        let (_guard, path, directory) = fixture();
        directory.write_json("a", &"1234", 64).unwrap();
        directory.write_json("b", &"5678", 64).unwrap();
        let limits = Limits {
            entry_bytes: 64,
            input_bytes: 10,
            retained_bytes: 1024,
            ..Limits::default()
        };
        let mut budget = ReadBudget::new(limits);
        assert_eq!(fs::metadata(path.join("a")).unwrap().len(), 6);
        assert_eq!(
            budget
                .read::<String>(&directory, "a", limits, |text| text.capacity())
                .unwrap(),
            "1234"
        );
        assert!(
            budget
                .read::<String>(&directory, "b", limits, |_| 0)
                .is_none()
        );
        let before = fs::read(path.join("a")).unwrap();
        assert!(directory.write_json("a", &"x".repeat(1000), 8).is_err());
        assert_eq!(fs::read(path.join("a")).unwrap(), before);
        let reader = directory.open_file("a").unwrap();
        assert!(
            fs::OpenOptions::new()
                .write(true)
                .open(path.join("a"))
                .is_err()
        );
        assert!(fs::rename(path.join("a"), path.join("moved")).is_err());
        assert!(directory.write_json("a", &"blocked", 64).is_err());
        drop(reader);
        assert_eq!(fs::read(path.join("a")).unwrap(), before);
        assert_eq!(
            fs::read_dir(&path)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<BTreeSet<_>>(),
            ["a", "b"]
                .map(std::ffi::OsString::from)
                .into_iter()
                .collect()
        );
        directory.write_json("a", &"new", 64).unwrap();
        assert_eq!(fs::read(path.join("a")).unwrap(), br#""new""#);
        let large = fs::OpenOptions::new()
            .write(true)
            .open(path.join("b"))
            .unwrap();
        large.set_len(8 * 1024 * 1024).unwrap();
        drop(large);
        assert!(
            ReadBudget::new(limits)
                .read::<String>(&directory, "b", limits, |_| panic!(
                    "oversize must not parse"
                ))
                .is_none()
        );
    }

    #[test]
    fn native_hardlinks_and_external_acl_grants_are_refused_without_repair() {
        let (_guard, path, directory) = fixture();
        directory.write_json("original", &"valid", 128).unwrap();
        fs::hard_link(path.join("original"), path.join("alias")).unwrap();
        let oracle = File::open(path.join("original")).unwrap();
        assert_eq!(
            query::<FILE_STANDARD_INFO>(&oracle, FileStandardInfo)
                .unwrap()
                .NumberOfLinks,
            2
        );
        drop(oracle);
        for name in ["original", "alias"] {
            assert!(directory.open_file(name).is_err());
            assert!(directory.remove(name).is_err());
            assert!(path.join(name).exists());
        }
        directory.write_json("public", &"valid", 128).unwrap();
        everyone(&path.join("public"));
        assert!(directory.open_file("public").is_err());
        assert_eq!(fs::read(path.join("public")).unwrap(), br#""valid""#);
        everyone(&path);
        assert!(Directory::open(&path, false).is_err());
        assert!(directory.write_json("rejected", &"data", 128).is_err());
        assert!(!path.join("rejected").exists());
    }

    // SDK installs a real protected Everyone grant, independently of SweepX's DACL factory.
    fn everyone(path: &Path) {
        let sddl: Vec<_> = "D:P(A;;FA;;;WD)".encode_utf16().chain([0]).collect();
        let mut descriptor = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        struct Descriptor(*mut std::ffi::c_void);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
            }
        }
        let _owner = Descriptor(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = ptr::null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        let path: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                )
            },
            0
        );
    }

    #[test]
    fn names_preserve_native_units_and_refuse_alternate_streams_or_unbounded_requests() {
        let raw = std::ffi::OsString::from_wide(&[b'a' as u16, 0xd800]);
        assert_eq!(component(&raw).unwrap(), [97, 0xd800]);
        for text in ["", ".", "..", "a/b", "a\\b", "a:stream", "a\0b"] {
            assert!(component(OsStr::new(text)).is_err(), "{text:?}");
        }
        assert!(component(OsStr::new(&"x".repeat(256))).is_err());
        for path in [
            r"\\server\share\cache",
            r"\\.\C:\cache",
            r"C:relative",
            r"\rooted",
            "C:\\bad\0path",
        ] {
            assert!(Directory::open(Path::new(path), false).is_err());
        }
    }
}
