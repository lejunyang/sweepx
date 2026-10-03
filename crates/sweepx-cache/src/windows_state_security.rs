//! Windows enforcement of a current-user-private state directory.
//!
//! This is the Windows counterpart to the Unix `0700` + owner check. It exists because the state
//! directory holds operation snapshots and cached scan previews, which describe the layout of a
//! user's disk; another account being able to read or, worse, replace them is the threat being
//! designed against.
//!
//! # Why an explicit DACL rather than trusting inheritance
//!
//! A directory created under `%LOCALAPPDATA%` normally inherits an ACL granting only SYSTEM,
//! Administrators and the owning user. That is the right shape, but inheriting it is not the same
//! as guaranteeing it: the profile ACL can be widened by policy, by an administrator, or by an
//! earlier version of an application that created the same path. So the directory is created with
//! a DACL written by this code and protected from inheritance, and the result is read back and
//! verified. Creating and checking are separate steps on purpose — the check is what runs on every
//! later open, when the directory already exists and was not created by us.
//!
//! # What is deliberately allowed
//!
//! SYSTEM and Administrators keep access. Refusing them would be security theatre: both can take
//! ownership of any file, so denying them changes nothing an attacker with those rights could not
//! undo, while breaking backup, antivirus and repair tooling. The property actually enforced is
//! that **no other ordinary user** appears in the DACL.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Security::{CreateWellKnownSid, EqualSid};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Security descriptor template granting full control to exactly the user, SYSTEM and
/// Administrators.
///
/// `P` protects the DACL from inheritance, which is the part that makes this a guarantee rather
/// than a default: without it a permissive ACE inherited from an ancestor would silently apply.
/// `OICI` propagates to files and subdirectories created later, so snapshots written into the
/// directory are covered without each write repeating the work.
///
/// `{USER}` is substituted with the calling token's SID. The obvious shorthand `OW` ("owner
/// rights") is deliberately **not** used: measured on this host, an `OW` ACE is stored literally
/// as the `S-1-3-4` placeholder rather than being resolved to the creating account, so the
/// directory would grant nothing to the user by name and the verification below correctly refuses
/// it.
const PRIVATE_DIR_SDDL_TEMPLATE: &str = "D:P(A;OICI;FA;;;{USER})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Formats a SID as its `S-1-...` string form for embedding in SDDL.
fn sid_to_string(sid: PSID) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

    let mut raw: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid SID; the returned buffer is freed below on every path.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if raw.is_null() {
        return Err(io::Error::other("Windows returned no SID string"));
    }
    // A supported SID has at most 15 subauthorities. Bound even its textual scan; Windows
    // guarantees a NUL-terminated allocation and every read stops at that terminator.
    let length = (0..256).find(|offset| unsafe { *raw.add(*offset) } == 0);
    let text = length.map(|length| {
        // SAFETY: these initialized units precede the SDK-supplied terminator.
        OsString::from_wide(unsafe { std::slice::from_raw_parts(raw, length) })
    });
    // SAFETY: freeing the buffer allocated by ConvertSidToStringSidW, exactly once.
    unsafe {
        LocalFree(raw as HLOCAL);
    }
    text.ok_or_else(|| io::Error::other("Windows SID text exceeds admission bounds"))?
        .into_string()
        .map_err(|_| io::Error::other("SID string was not valid UTF-16"))
}

/// Creates `path` with an explicit current-user-private DACL.
///
/// Returns `Ok(false)` when the directory already exists, leaving verification to
/// [`is_private_owned_directory`]: an existing directory may have been created by something else, and
/// silently rewriting its ACL would hide exactly the misconfiguration worth reporting.
pub fn create_private_dir(path: &Path) -> io::Result<bool> {
    let target = wide(path.as_os_str())?;
    let descriptor = PrivateSecurityDescriptor::new()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: both pointers remain valid for this synchronous call.
    let created = unsafe { CreateDirectoryW(target.as_ptr(), &attributes) };
    let error = io::Error::last_os_error();
    if created != 0 {
        return Ok(true);
    }
    // ERROR_ALREADY_EXISTS
    if error.raw_os_error() == Some(183) {
        return Ok(false);
    }
    Err(error)
}

/// One protected current-user/SYSTEM/Administrators DACL, shared by pathname and relative opens.
/// The allocation remains live throughout the synchronous creation call and is freed once.
pub(crate) struct PrivateSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl PrivateSecurityDescriptor {
    /// Creates the protected policy without inheriting grants from an existing parent.
    pub(crate) fn new() -> io::Result<Self> {
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let user = current_user_sid()?;
        let user_text = sid_to_string(user.as_ptr() as PSID)?;
        let sddl = wide(OsStr::new(
            &PRIVATE_DIR_SDDL_TEMPLATE.replace("{USER}", &user_text),
        ))?;
        // SAFETY: `sddl` is a NUL-terminated UTF-16 buffer that outlives the call, and the descriptor
        // out-parameter is freed below on every path.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor.is_null() {
            return Err(io::Error::other(
                "Windows returned no private security descriptor",
            ));
        }
        Ok(Self(descriptor))
    }

    /// Borrows the SDK allocation only while this owner remains live during native creation.
    pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for PrivateSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: conversion allocated this descriptor; this RAII owner frees it exactly once.
        unsafe { LocalFree(self.0 as HLOCAL) };
    }
}

/// A Windows-allocated descriptor and its borrowed owner/DACL pointers.
/// All borrows end before the single LocalFree in Drop.
struct ObjectSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}

impl Drop for ObjectSecurity {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocated this descriptor on success; this owner frees it once.
        unsafe { LocalFree(self.descriptor as HLOCAL) };
    }
}

impl ObjectSecurity {
    fn from_file(file: &std::fs::File) -> io::Result<Self> {
        let mut result = Self {
            descriptor: ptr::null_mut(),
            owner: ptr::null_mut(),
            dacl: ptr::null_mut(),
        };
        // SAFETY: the caller retains a READ_CONTROL handle; output borrows belong to descriptor.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut result.owner,
                ptr::null_mut(),
                &mut result.dacl,
                ptr::null_mut(),
                &mut result.descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if result.descriptor.is_null() {
            return Err(io::Error::other("Windows returned no security descriptor"));
        }
        Ok(result)
    }

    fn private(&self) -> io::Result<bool> {
        // NULL DACL grants everyone full control. An absent owner is not trusted either.
        if self.dacl.is_null() || self.owner.is_null() {
            return Ok(false);
        }
        let owner = copy_sid(self.owner)?;
        let user = current_user_sid()?;
        let system = well_known_sid(WinLocalSystemSid)?;
        let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        // SAFETY: GetSecurityInfo supplies a complete native ACL within its live allocation;
        // AclSize is a u16, bounding the borrowed bytes to at most 65,535. The portable parser
        // checks header, count, ACE and SID boundaries before interpreting any grant.
        let bytes = unsafe {
            std::slice::from_raw_parts(self.dacl.cast::<u8>(), usize::from((*self.dacl).AclSize))
        };
        Ok(crate::windows_state_policy::is_private_acl(
            bytes,
            &[
                owner.as_bytes(),
                user.as_bytes(),
                system.as_bytes(),
                administrators.as_bytes(),
            ],
        ))
    }

    fn owned(&self) -> io::Result<bool> {
        if self.owner.is_null() {
            return Ok(false);
        }
        let owner = copy_sid(self.owner)?;
        let user = current_user_sid()?;
        if owner == user || owner == current_token_owner_sid()? {
            return Ok(true);
        }
        // An elevated run leaves Administrators as owner. Accept it only when this user's
        // filtered/elevated token actually contains that group, retaining the existing policy.
        Ok(
            owner == well_known_sid(WinBuiltinAdministratorsSid)?
                && current_user_is_admin_member()?,
        )
    }
}

/// Opens a directory without following its final reparse point or recalling offline content.
/// Ancestor admission is still the state caller's separate contract; this does not turn a
/// pathname into retained authority for later snapshot/cache operations.
fn open_directory(path: &Path) -> io::Result<std::fs::File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
        )
        .open(path)?;
    let metadata = file.metadata()?;
    let refused = FILE_ATTRIBUTE_REPARSE_POINT
        | FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    if !metadata.is_dir() || metadata.file_attributes() & refused != 0 {
        return Err(io::Error::other(
            "private state is not an ordinary online directory",
        ));
    }
    Ok(file)
}

/// Checks privacy and controlled ownership from the same opened directory and descriptor.
/// A reparse/offline object is refused before the handle security query; unknown ACE types fail
/// closed. This is an observation at this instant, not ongoing authority for later path opens.
pub fn is_private_owned_directory(path: &Path) -> io::Result<bool> {
    let file = open_directory(path)?;
    is_private_owned_handle(&file)
}

/// Observes controlled owner/DACL from a retained READ_CONTROL file handle.
/// The caller independently checks object type, reparse/provider and mount boundaries. This
/// shared check never grants authority for another pathname or persists a permission verdict.
pub(crate) fn is_private_owned_handle(file: &std::fs::File) -> io::Result<bool> {
    let security = ObjectSecurity::from_file(file)?;
    Ok(security.private()? && security.owned()?)
}

/// Test surface for independently checking the created DACL through a native handle.
#[cfg(test)]
pub fn is_current_user_private(path: &Path) -> io::Result<bool> {
    ObjectSecurity::from_file(&open_directory(path)?)?.private()
}

/// Test surface for controlled owner checks, including elevated/filtered token ownership.
#[cfg(test)]
pub fn is_owned_by_current_user(path: &Path) -> io::Result<bool> {
    ObjectSecurity::from_file(&open_directory(path)?)?.owned()
}

/// Whether this user is an Administrators member, counting a filtered token's deny-only group.
///
/// `CheckTokenMembership` alone is not enough and this was measured, not assumed: on this host an
/// unelevated admin user returns **false**, because UAC hands the process a *filtered* token in
/// which Administrators is present but marked deny-only. Trusting that answer left the ordinary
/// unelevated run locked out of a directory an elevated run had created.
///
/// So the group list is read directly and the SID is matched regardless of its deny-only flag: the
/// question here is "could this user reach the directory by elevating", not "is it elevated right
/// now". A user genuinely outside the group has no such entry and is still refused.
fn current_user_is_admin_member() -> io::Result<bool> {
    use windows_sys::Win32::Security::{SID_AND_ATTRIBUTES, TOKEN_GROUPS, TokenGroups};
    let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
    let buffer = TokenBuffer::read(TokenGroups)?;
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    if buffer.bytes < offset {
        return Err(io::Error::other("truncated Windows token group header"));
    }
    // SAFETY: the bounded, aligned buffer contains the u32 GroupCount header. We do not
    // materialize TOKEN_GROUPS's one-element array before checking the actual variable count.
    let count = unsafe { buffer.words.as_ptr().cast::<u32>().read() } as usize;
    let needed = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|bytes| offset.checked_add(bytes));
    if needed.is_none_or(|needed| needed > buffer.bytes) {
        return Err(io::Error::other("truncated Windows token groups"));
    }
    // SAFETY: native offset, pointer alignment and complete array bounds were checked above;
    // SID pointers are the Windows-provided inline token SIDs and outlive this iteration.
    let entries = unsafe {
        std::slice::from_raw_parts(
            buffer
                .words
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    Ok(entries
        .iter()
        .any(|entry| sid_equals(entry.Sid, administrators.as_ptr() as PSID)))
}

/// An aligned, bounded token information allocation. All errors release the token handle;
/// excessive sizes and malformed returned bounds are refused before pointer interpretation.
struct TokenBuffer {
    words: Vec<usize>,
    bytes: usize,
}

impl TokenBuffer {
    fn read(class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS) -> io::Result<Self> {
        use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY};
        let mut raw = ptr::null_mut();
        // SAFETY: process pseudo-handle needs no release; successful token ownership moves below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcessToken returned a fresh valid token handle owned exactly once.
        let token = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let mut needed = 0u32;
        // SAFETY: zero-length size query; token stays live on every error/return path.
        let queried = unsafe {
            GetTokenInformation(
                token.as_raw_handle().cast(),
                class,
                ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if queried == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(122) {
                // ERROR_INSUFFICIENT_BUFFER
                return Err(error);
            }
        }
        let count = crate::windows_state_policy::token_buffer_words(needed).ok_or_else(|| {
            io::Error::other("Windows token information exceeds admission bounds")
        })?;
        let requested = needed;
        let mut words = vec![0usize; count];
        // SAFETY: pointer-aligned storage has at least requested bytes; token stays owned here.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle().cast(),
                class,
                words.as_mut_ptr().cast(),
                requested,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if needed == 0 || needed > requested {
            return Err(io::Error::other(
                "Windows returned invalid token information bounds",
            ));
        }
        Ok(Self {
            words,
            bytes: needed as usize,
        })
    }

    fn pointer<T>(&self) -> io::Result<*const T> {
        if self.bytes < size_of::<T>() || align_of::<T>() > align_of::<usize>() {
            return Err(io::Error::other(
                "truncated or misaligned Windows token structure",
            ));
        }
        Ok(self.words.as_ptr().cast())
    }
}

/// Reads the owner SID assigned by the current token, including the elevated owner policy.
fn current_token_owner_sid() -> io::Result<OwnedSid> {
    use windows_sys::Win32::Security::{TOKEN_OWNER, TokenOwner};
    let buffer = TokenBuffer::read(TokenOwner)?;
    let owner = buffer.pointer::<TOKEN_OWNER>()?;
    // SAFETY: the checked aligned buffer contains TOKEN_OWNER and its Windows-provided SID.
    copy_sid(unsafe { (*owner).Owner })
}

/// Reads the current process token's user SID into bounded owned storage.
fn current_user_sid() -> io::Result<OwnedSid> {
    use windows_sys::Win32::Security::{TOKEN_USER, TokenUser};
    let buffer = TokenBuffer::read(TokenUser)?;
    let user = buffer.pointer::<TOKEN_USER>()?;
    // SAFETY: the checked aligned buffer contains TOKEN_USER and its Windows-provided SID.
    copy_sid(unsafe { (*user).User.Sid })
}

/// Copies a native SID while its Windows-owned allocation is live. A SID has at most 15
/// subauthorities, so malformed/unsupported values are refused rather than retained unboundedly.
fn copy_sid(sid: PSID) -> io::Result<OwnedSid> {
    use windows_sys::Win32::Security::GetLengthSid;
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::other("Windows returned an invalid SID"));
    }
    // SAFETY: Windows validated the SID; the API returns its size within its live allocation.
    let length = unsafe { GetLengthSid(sid) } as usize;
    if !(8..=68).contains(&length) {
        return Err(io::Error::other("Windows SID exceeds admission bounds"));
    }
    let mut owned = OwnedSid {
        words: [0; 17],
        length,
    };
    // SAFETY: the validated native SID has length bytes; initialized DWORD-aligned storage
    // holds at most 68 bytes. Copying bytes does not require source DWORD alignment.
    unsafe {
        ptr::copy_nonoverlapping(sid.cast::<u8>(), owned.words.as_mut_ptr().cast(), length);
    }
    Ok(owned)
}

/// Bounded DWORD-aligned storage for native SID APIs; Vec<u8> provides no alignment contract.
/// Unused words stay zero so value comparison includes no uninitialized or allocator padding.
#[derive(PartialEq, Eq)]
struct OwnedSid {
    words: [u32; 17],
    length: usize,
}

impl OwnedSid {
    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: constructor validates 8..=68 bytes; all 17 words are initialized.
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.length) }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// Materializes a well-known SID into an owned buffer.
fn well_known_sid(kind: i32) -> io::Result<OwnedSid> {
    let mut size = 0u32;
    // SAFETY: size query; failure with a zero buffer is expected and inspected below.
    unsafe {
        CreateWellKnownSid(kind, ptr::null_mut(), ptr::null_mut(), &mut size);
    }
    if !(8..=68).contains(&size) {
        return Err(io::Error::other(
            "well-known Windows SID exceeds admission bounds",
        ));
    }
    // SID's maximum native size is 68 bytes. u32 storage preserves its native alignment.
    let mut buffer = [0u32; 17];
    // SAFETY: the aligned fixed buffer holds the requested SID and lives through validation.
    let ok =
        unsafe { CreateWellKnownSid(kind, ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut size) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if !(8..=68).contains(&size) {
        return Err(io::Error::other(
            "Windows returned invalid well-known SID bounds",
        ));
    }
    copy_sid(buffer.as_mut_ptr().cast())
}

/// Compares two SIDs by value.
fn sid_equals(left: PSID, right: PSID) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    // SAFETY: both pointers are valid SIDs for the duration of the comparison.
    unsafe { EqualSid(left, right) != 0 }
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    crate::windows_state_policy::terminated_utf16(value.encode_wide()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows name is oversized or contains NUL",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;

    /// Fixture-only OS installation of a basic foreign grant, independent of the checker.
    fn install_everyone_read(path: &Path) {
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        use windows_sys::Win32::Security::{
            ACL_REVISION, AddAccessAllowedAce, InitializeAcl, WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
        let everyone = well_known_sid(WinWorldSid).unwrap();
        let mut storage = [0u32; 128];
        let acl = storage.as_mut_ptr().cast::<ACL>();
        // SAFETY: live aligned ACL storage and SID; SDK validates the complete initialized ACL.
        assert_ne!(unsafe { InitializeAcl(acl, 512, ACL_REVISION) }, 0);
        assert_ne!(
            unsafe {
                AddAccessAllowedAce(
                    acl,
                    ACL_REVISION,
                    FILE_GENERIC_READ,
                    everyone.as_ptr().cast_mut().cast(),
                )
            },
            0
        );
        let target = wide(path.as_os_str()).unwrap();
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    target.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                )
            },
            ERROR_SUCCESS
        );
    }

    /// A directory this code creates must pass both checks it will later be judged by.
    ///
    /// Creation and verification are separate implementations, so this is the test that keeps
    /// them agreeing: writing a DACL the checker rejects would make durable state unusable.
    #[test]
    fn a_created_private_directory_passes_its_own_checks() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("state");
        assert!(create_private_dir(&dir).unwrap(), "directory was created");
        assert!(dir.is_dir());
        assert!(
            is_current_user_private(&dir).unwrap(),
            "a directory created with the private DACL must be accepted by the checker"
        );
        assert!(is_owned_by_current_user(&dir).unwrap());
        assert!(is_private_owned_directory(&dir).unwrap());
    }

    /// Install a real object allow ACE through the OS rather than manufacturing the bytes
    /// handed to the privacy checker. The old checker skipped this granting ACE type entirely.
    #[test]
    fn an_os_installed_object_grant_is_not_mistaken_for_private_state() {
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        use windows_sys::Win32::Security::{
            ACE_HEADER, ACL_REVISION_DS, AddAccessAllowedAce, AddAccessAllowedObjectAce, GetAce,
            InitializeAcl, WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_GENERIC_READ};
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("object-grant");
        create_private_dir(&path).unwrap();
        let mut storage = [0u32; 128];
        let acl = storage.as_mut_ptr().cast::<ACL>();
        let everyone = well_known_sid(WinWorldSid).unwrap();
        let user = current_user_sid().unwrap();
        // SAFETY: aligned 512-byte ACL storage and live SID; SDK functions validate all bounds.
        assert_ne!(
            unsafe { InitializeAcl(acl, size_of_val(&storage) as u32, ACL_REVISION_DS) },
            0
        );
        // Retain a basic user grant so refusal does not depend on the filesystem's effective
        // access treatment of an object ACE. The old checker skipped the later unknown grant.
        assert_ne!(
            unsafe {
                AddAccessAllowedAce(
                    acl,
                    ACL_REVISION_DS,
                    FILE_ALL_ACCESS,
                    user.as_ptr().cast_mut().cast(),
                )
            },
            0
        );
        assert_ne!(
            unsafe {
                AddAccessAllowedObjectAce(
                    acl,
                    ACL_REVISION_DS,
                    0,
                    FILE_GENERIC_READ,
                    ptr::null(),
                    ptr::null(),
                    everyone.as_ptr().cast_mut().cast(),
                )
            },
            0
        );
        let target = wide(path.as_os_str()).unwrap();
        // SAFETY: native ACL and path remain live; only this isolated directory's DACL changes.
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    target.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                )
            },
            ERROR_SUCCESS
        );
        // Verify what Windows actually stored through the independent named-security API.
        let mut stored_acl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetNamedSecurityInfoW(
                    target.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut stored_acl,
                    ptr::null_mut(),
                    &mut descriptor,
                )
            },
            ERROR_SUCCESS
        );
        // Capture before assertions so the allocation is freed even if the fixture differs.
        let mut stored_types = std::collections::BTreeSet::new();
        let count = if stored_acl.is_null() {
            0
        } else {
            // SAFETY: successful query returned a complete ACL inside the live descriptor.
            unsafe { (*stored_acl).AceCount }
        };
        for index in 0..u32::from(count) {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(stored_acl, index, &mut ace) } != 0 && !ace.is_null() {
                // SAFETY: successful GetAce returns a header inside the live descriptor.
                stored_types.insert(unsafe { (*ace.cast::<ACE_HEADER>()).AceType });
            }
        }
        // SAFETY: descriptor was allocated by the successful named-security query.
        unsafe { LocalFree(descriptor as HLOCAL) };
        assert_eq!(count, 2);
        assert_eq!(
            stored_types,
            [0, 5].into(),
            "fixture must contain both actual grant layouts"
        );
        assert!(!is_current_user_private(&path).unwrap());
        assert!(!is_private_owned_directory(&path).unwrap());
    }

    /// A security observation must remain attached to its opened object after a pathname swap.
    #[test]
    fn descriptor_observation_stays_with_the_opened_directory_after_rename() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("original");
        let retained = temp.path().join("retained");
        create_private_dir(&path).unwrap();
        let file = open_directory(&path).unwrap();
        std::fs::rename(&path, &retained).unwrap();
        create_private_dir(&path).unwrap();
        install_everyone_read(&path);
        assert!(!is_private_owned_directory(&path).unwrap());
        let security = ObjectSecurity::from_file(&file).unwrap();
        assert!(security.private().unwrap());
        assert!(security.owned().unwrap());
        assert!(is_private_owned_directory(&retained).unwrap());
        assert!(path.is_dir());
    }

    /// Creating over an existing directory reports "not created" rather than rewriting its ACL.
    #[test]
    fn creating_an_existing_directory_reports_it_without_rewriting() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("state");
        assert!(create_private_dir(&dir).unwrap());
        assert!(
            !create_private_dir(&dir).unwrap(),
            "an existing directory must be reported, not silently re-secured"
        );
    }

    /// Widening the DACL to another real user must be detected.
    ///
    /// Uses a SID that always exists and is never the owner, SYSTEM or Administrators, so the
    /// test exercises the actual rejection path rather than a synthetic one.
    #[test]
    fn a_directory_shared_with_another_trustee_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("state");
        create_private_dir(&dir).unwrap();
        assert!(is_current_user_private(&dir).unwrap());

        // Grant Everyone read access through the OS's own tool, so the ACL is modified the same
        // way a misconfiguration in the wild would be.
        let status = std::process::Command::new("icacls")
            .arg(&dir)
            .arg("/grant")
            .arg("*S-1-1-0:(OI)(CI)R")
            .output()
            .expect("icacls runs");
        assert!(
            status.status.success(),
            "icacls failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert!(
            !is_current_user_private(&dir).unwrap(),
            "a directory readable by Everyone must be refused"
        );
    }

    /// A missing path must surface as an error rather than a confident "private".
    #[test]
    fn a_missing_directory_is_an_error_not_a_pass() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("absent");
        assert!(is_current_user_private(&missing).is_err());
    }

    /// An Administrators-owned directory stays usable for a member of that group.
    ///
    /// This is the lockout case, and it is asserted **unelevated**, which is where the damage was:
    /// an elevated run leaves `S-1-5-32-544` as the owner on disk, and every later ordinary run has
    /// to keep working against it. Reassigning the owner needs a privilege an ordinary user lacks,
    /// so the fixture is built with `icacls` under whatever rights are available and the test
    /// asserts only once the owner really changed — a skip here would hide the regression it exists
    /// to catch, so the reason is printed.
    #[test]
    fn an_administrators_owned_directory_stays_usable() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("state");
        create_private_dir(&dir).unwrap();

        let status = std::process::Command::new("icacls")
            .arg(&dir)
            .arg("/setowner")
            .arg("*S-1-5-32-544")
            .output()
            .expect("icacls runs");

        let owner_reassigned = status.status.success()
            && !is_owner_the_token_user(&dir).expect("owner is readable after icacls");
        if !owner_reassigned {
            eprintln!(
                "SKIP: could not reassign owner to Administrators ({}). \
                 The elevated end-to-end run covers this case.",
                String::from_utf8_lossy(&status.stderr).trim()
            );
            return;
        }

        assert!(
            is_owned_by_current_user(&dir).unwrap(),
            "an Administrators-owned directory must stay usable for a group member, \
             or one elevated run permanently locks the user out of durable state"
        );
        assert!(
            is_current_user_private(&dir).unwrap(),
            "reassigning the owner must not widen the privacy verdict"
        );
    }

    /// Whether `path`'s owner is literally the token's user SID, used to confirm a fixture took.
    fn is_owner_the_token_user(path: &Path) -> io::Result<bool> {
        let target = wide(path.as_os_str())?;
        let mut owner: PSID = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: out-parameters belong to `descriptor`, freed once below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                target.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let user = current_user_sid()?;
        let verdict = !owner.is_null() && sid_equals(owner, user.as_ptr() as PSID);
        // SAFETY: freed exactly once after the read above.
        unsafe {
            LocalFree(descriptor as HLOCAL);
        }
        Ok(verdict)
    }

    /// A directory owned by an unrelated account is still refused.
    ///
    /// Keeps the Administrators allowance from becoming a blanket pass: the check must reject an
    /// owner the user genuinely does not control. `S-1-5-18` (SYSTEM) stands in for that, since it
    /// is a real SID that is neither the user, the token owner, nor Administrators.
    #[test]
    fn a_directory_owned_by_an_unrelated_account_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("state");
        create_private_dir(&dir).unwrap();

        let status = std::process::Command::new("icacls")
            .arg(&dir)
            .arg("/setowner")
            .arg("*S-1-5-18")
            .output()
            .expect("icacls runs");
        if !status.status.success() {
            eprintln!(
                "SKIP: could not reassign owner to SYSTEM: {}",
                String::from_utf8_lossy(&status.stderr).trim()
            );
            return;
        }

        assert!(
            !is_owned_by_current_user(&dir).unwrap(),
            "an owner the user does not control must be refused"
        );
    }

    /// Administrators membership is detected even from an unelevated filtered token.
    ///
    /// Pins the measured behavior that the fix turns on, because the obvious API gets it wrong:
    /// `CheckTokenMembership` returns **false** for an unelevated admin user, since UAC marks the
    /// group deny-only in the filtered token. Reading the group list directly returns true. If this
    /// ever regressed, an elevated run would again lock the user out of durable state, and the
    /// symptom would look like a permissions bug rather than a membership one.
    ///
    /// Cross-checked against the OS's own answer via `whoami /groups`, so the assertion is not this
    /// code agreeing with itself.
    #[test]
    fn administrators_membership_survives_token_filtering() {
        let ours = current_user_is_admin_member().expect("membership is readable");

        let output = std::process::Command::new("whoami")
            .arg("/groups")
            .arg("/fo")
            .arg("csv")
            .output()
            .expect("whoami runs");
        let text = String::from_utf8_lossy(&output.stdout);
        let os_says = text.contains("S-1-5-32-544");

        assert_eq!(
            ours, os_says,
            "membership must match what the OS reports, including a deny-only group entry"
        );
    }

    /// The token reports both a user and an owner SID, differing only under elevation.
    ///
    /// Pins the mechanism the fix depends on: if `TokenOwner` stopped being readable, the elevated
    /// path would silently fall back to the user comparison and fail again.
    #[test]
    fn the_token_reports_both_a_user_and_an_owner_sid() {
        let user = current_user_sid().expect("token user SID is readable");
        let owner = current_token_owner_sid().expect("token owner SID is readable");
        assert!(!user.is_empty() && !owner.is_empty());
        let elevated = std::process::Command::new("net")
            .arg("session")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !elevated {
            assert!(
                sid_equals(user.as_ptr() as PSID, owner.as_ptr() as PSID),
                "unelevated, the owner SID is the user's own"
            );
        }
    }
}
