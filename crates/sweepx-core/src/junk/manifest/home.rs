//! Native user-home input, separate from path admission and configuration authority.
//! Called once on a Cargo observation's worker; host directory services are synchronous and
//! may block. The caller checks cancellation/deadline before and after, and never persists it.
use std::ffi::OsString;

#[cfg(unix)]
/// Observes the real user's passwd home using one bounded caller buffer; no directory is opened.
pub(super) fn lookup() -> Result<OsString, &'static str> {
    use std::os::unix::ffi::OsStringExt;
    // A single fixed request bounds caller storage and work even for NSS implementations
    // requesting a larger passwd record. ERANGE is incomplete evidence, never home absence.
    let mut buffer = vec![0_u8; 64 * 1024];
    // SAFETY: initialized output storage for passwd's scalar and pointer fields; getpwuid_r
    // writes it and the caller-owned buffer. No process-global passwd storage is borrowed.
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    // SAFETY: getuid only queries this process's current real user identity.
    let uid = unsafe { libc::getuid() };
    // SAFETY: these output pointers and buffer remain valid across the synchronous call.
    // Use real UID, matching Cargo's user-home lookup rather than effective credentials.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status == libc::ERANGE {
        return Err("resource_limit");
    }
    if status != 0 {
        return Err("cargo_home_lookup_failed");
    }
    if result.is_null() {
        return Err("cargo_home_unavailable");
    }
    if !std::ptr::eq(result, &record) || record.pw_uid != uid || record.pw_dir.is_null() {
        return Err("cargo_home_lookup_failed");
    }
    // POSIX puts the record's strings in the supplied buffer. Validate the native pointer
    // against that allocation and find NUL within it; never do an unbounded CStr read.
    let offset = (record.pw_dir as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .filter(|offset| *offset < buffer.len())
        .ok_or("cargo_home_lookup_failed")?;
    let remaining = &buffer[offset..];
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("resource_limit")?;
    Ok(OsString::from_vec(remaining[..length].to_vec()))
}

#[cfg(windows)]
/// Observes the current Profile spelling without directory verification or creation.
pub(super) fn lookup() -> Result<OsString, &'static str> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_Profile, KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath,
    };
    struct NativePath(*mut u16);
    impl Drop for NativePath {
        fn drop(&mut self) {
            // SAFETY: SHGetKnownFolderPath transfers this allocation even on failure;
            // CoTaskMemFree accepts null, and this guard frees it exactly once.
            unsafe { CoTaskMemFree(self.0.cast()) }
        }
    }
    let mut path = NativePath(std::ptr::null_mut());
    // SAFETY: a null token selects the current user. DONT_VERIFY retrieves the spelling
    // without creating/verifying the directory; later native path admission remains separate.
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_Profile,
            KF_FLAG_DONT_VERIFY as u32,
            std::ptr::null_mut(),
            &mut path.0,
        )
    };
    if status < 0 || path.0.is_null() {
        return Err("cargo_home_lookup_failed");
    }
    for length in 0..32 * 1024 {
        // SAFETY: the successful API supplies a terminated UTF-16 string. Stop at NUL
        // and cap traversal/copying; any native allocation is released on all exits.
        if unsafe { *path.0.add(length) } == 0 {
            if length == 0 {
                return Err("cargo_home_unavailable");
            }
            // SAFETY: the prefix preceding this terminator is live in the native allocation.
            return Ok(OsString::from_wide(unsafe {
                std::slice::from_raw_parts(path.0, length)
            }));
        }
    }
    Err("resource_limit")
}
