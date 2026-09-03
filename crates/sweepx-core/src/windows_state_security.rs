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
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, ACE_HEADER, CreateWellKnownSid, EqualSid};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetAce, IsValidSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
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
    // SAFETY: on success the API returns a NUL-terminated UTF-16 string.
    let mut length = 0usize;
    // SAFETY: walking to the terminator of the buffer the API just produced.
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` units precede the terminator.
    let text = OsString::from_wide(unsafe { std::slice::from_raw_parts(raw, length) });
    // SAFETY: freeing the buffer allocated by ConvertSidToStringSidW, exactly once.
    unsafe {
        LocalFree(raw as HLOCAL);
    }
    text.into_string()
        .map_err(|_| io::Error::other("SID string was not valid UTF-16"))
}

/// Creates `path` with an explicit current-user-private DACL.
///
/// Returns `Ok(false)` when the directory already exists, leaving verification to
/// [`is_current_user_private`]: an existing directory may have been created by something else, and
/// silently rewriting its ACL would hide exactly the misconfiguration worth reporting.
pub fn create_private_dir(path: &Path) -> io::Result<bool> {
    let target = wide(path.as_os_str());
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let user = current_user_sid()?;
    let user_text = sid_to_string(user.as_ptr() as PSID)?;
    let sddl = wide(OsStr::new(
        &PRIVATE_DIR_SDDL_TEMPLATE.replace("{USER}", &user_text),
    ));
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
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: both pointers remain valid for this synchronous call.
    let created = unsafe { CreateDirectoryW(target.as_ptr(), &attributes) };
    let error = io::Error::last_os_error();
    // SAFETY: `descriptor` came from the conversion above and is freed exactly once.
    unsafe {
        LocalFree(descriptor as HLOCAL);
    }
    if created != 0 {
        return Ok(true);
    }
    // ERROR_ALREADY_EXISTS
    if error.raw_os_error() == Some(183) {
        return Ok(false);
    }
    Err(error)
}

/// Whether `path`'s DACL grants access to nobody except its owner, SYSTEM and Administrators.
///
/// Reads the actual descriptor rather than trusting how the directory was created, because this
/// runs against directories created by earlier runs, by other tools, or by a user following a
/// setup guide.
///
/// Fails closed: any ACE that cannot be inspected, a missing DACL (which means "grant everyone"),
/// or an unreadable owner all return `false`.
pub fn is_current_user_private(path: &Path) -> io::Result<bool> {
    let target = wide(path.as_os_str());
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: all out-parameters are owned by the returned descriptor, freed once below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            target.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let verdict = (|| {
        // A NULL DACL grants everyone full control. Treat it as the hard failure it is.
        if dacl.is_null() || owner.is_null() {
            return Ok(false);
        }
        let system = well_known_sid(WinLocalSystemSid)?;
        let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        // The calling user is accepted alongside the recorded owner. They are normally the same,
        // but a directory whose owner was reassigned (for example by an administrator) can still
        // legitimately grant the user access, and ownership is separately enforced by
        // `is_owned_by_current_user`.
        let current_user = current_user_sid()?;
        // SAFETY: a non-null DACL from GetNamedSecurityInfoW is a valid ACL for the descriptor's
        // lifetime.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut ace: *mut core::ffi::c_void = ptr::null_mut();
            // SAFETY: `index` is below the reported ACE count.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                return Ok(false);
            }
            // SAFETY: GetAce yields a header-prefixed ACE within the ACL allocation.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            // Only allow-ACEs widen access; a deny-ACE can never grant another user anything.
            const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            // SAFETY: an allow-ACE is laid out as ACCESS_ALLOWED_ACE with the SID inline at
            // SidStart; taking its address is how the Win32 API defines reading the trustee.
            let allowed = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
            let sid = ptr::from_ref(&allowed.SidStart) as PSID;
            // SAFETY: the SID lives inside the ACL allocation, which outlives this loop.
            if unsafe { IsValidSid(sid) } == 0 {
                return Ok(false);
            }
            if sid_equals(sid, owner)
                || sid_equals(sid, current_user.as_ptr() as PSID)
                || sid_equals(sid, system.as_ptr() as PSID)
                || sid_equals(sid, administrators.as_ptr() as PSID)
            {
                continue;
            }
            // Some other trustee can reach the directory.
            return Ok(false);
        }
        Ok(true)
    })();
    // SAFETY: freed exactly once, after every read of the borrowed pointers above.
    unsafe {
        LocalFree(descriptor as HLOCAL);
    }
    verdict
}

/// Whether `path`'s owner is a principal this user controls.
///
/// Separate from the DACL check because they answer different questions: the DACL says who *may*
/// reach the directory, ownership says whether it is ours to trust. A directory owned by another
/// *ordinary* account can have its permissions rewritten by that account at any time.
///
/// Accepts the token's user SID, the token's owner SID, and Administrators when the user is a
/// member of it. The last two are not cosmetic. Measured on this host: unelevated, user and owner
/// are both `S-1-5-21-…-1001`; elevated, the user is unchanged but the owner becomes
/// `S-1-5-32-544` (Administrators), so **every directory an elevated run creates is owned by
/// Administrators and keeps that owner on disk**. Comparing only against the user SID produced two
/// failures found by running the binary rather than the tests: an elevated run rejected the state
/// directory it had just created, and afterwards every unelevated run was permanently locked out of
/// it.
///
/// Accepting Administrators concedes nothing new: [`is_current_user_private`] already allows that
/// group for the same reason, since it can take ownership of any object regardless. Membership is
/// checked against the token rather than assumed, so a non-member user still rejects an
/// Administrators-owned directory it genuinely does not control.
pub fn is_owned_by_current_user(path: &Path) -> io::Result<bool> {
    let target = wide(path.as_os_str());
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
    let verdict = (|| {
        if owner.is_null() {
            return Ok(false);
        }
        let user = current_user_sid()?;
        if sid_equals(owner, user.as_ptr() as PSID) {
            return Ok(true);
        }
        let token_owner = current_token_owner_sid()?;
        if sid_equals(owner, token_owner.as_ptr() as PSID) {
            return Ok(true);
        }
        // An elevated run leaves Administrators as the owner. The same user unelevated must still
        // be able to use that directory, otherwise one elevated run bricks durable state.
        let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        if sid_equals(owner, administrators.as_ptr() as PSID) && current_user_is_admin_member()? {
            return Ok(true);
        }
        Ok(false)
    })();
    // SAFETY: freed exactly once after the borrow above.
    unsafe {
        LocalFree(descriptor as HLOCAL);
    }
    verdict
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
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::GetTokenInformation;
    use windows_sys::Win32::Security::{TOKEN_GROUPS, TOKEN_QUERY, TokenGroups};

    let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
    let mut token = ptr::null_mut();
    // SAFETY: the pseudo-handle needs no release; `token` is closed below on every path.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut needed = 0u32;
    // SAFETY: deliberate size query with a zero-length buffer.
    unsafe {
        GetTokenInformation(token, TokenGroups, ptr::null_mut(), 0, &mut needed);
    }
    let mut buffer = vec![0u8; needed.max(1) as usize];
    // SAFETY: `buffer` is at least `needed` bytes and outlives the call.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    // SAFETY: closing the token opened above, exactly once.
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer begins with TOKEN_GROUPS, whose Groups array of GroupCount
    // entries is laid out inline immediately after the count.
    let groups = unsafe { &*(buffer.as_ptr() as *const TOKEN_GROUPS) };
    let count = groups.GroupCount as usize;
    // SAFETY: the array has `count` entries inside the buffer just filled by the API.
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
    Ok(entries
        .iter()
        .any(|entry| sid_equals(entry.Sid, administrators.as_ptr() as PSID)))
}

/// Reads the SID this token assigns as owner to objects it creates.
///
/// Distinct from [`current_user_sid`] under elevation, where it is the Administrators group. This
/// is read from the token rather than assumed, so a machine whose token is configured differently
/// is judged by what it actually reports.
fn current_token_owner_sid() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::GetTokenInformation;
    use windows_sys::Win32::Security::{TOKEN_OWNER, TOKEN_QUERY, TokenOwner};

    let mut token = ptr::null_mut();
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no release; `token` is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut needed = 0u32;
    // SAFETY: a deliberate size query; a zero-length buffer is the documented way to ask.
    unsafe {
        GetTokenInformation(token, TokenOwner, ptr::null_mut(), 0, &mut needed);
    }
    let mut buffer = vec![0u8; needed.max(1) as usize];
    // SAFETY: `buffer` is at least `needed` bytes and outlives the call.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenOwner,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    // SAFETY: closing the token opened above, exactly once.
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with a TOKEN_OWNER whose SID points inside it.
    let owner = unsafe { &*(buffer.as_ptr() as *const TOKEN_OWNER) };
    Ok(copy_sid(owner.Owner))
}

/// Reads the current process token's user SID into an owned buffer.
fn current_user_sid() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::GetTokenInformation;
    use windows_sys::Win32::Security::{TOKEN_QUERY, TOKEN_USER, TokenUser};

    let mut token = ptr::null_mut();
    // SAFETY: the pseudo-handle from GetCurrentProcess needs no release; `token` is closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut needed = 0u32;
    // SAFETY: a deliberate size query; a zero-length buffer is the documented way to ask.
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    let mut buffer = vec![0u8; needed.max(1) as usize];
    // SAFETY: `buffer` is at least `needed` bytes and outlives the call.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    // SAFETY: closing the token opened above, exactly once.
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside it.
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    Ok(copy_sid(user.User.Sid))
}

/// Copies a SID into an owned buffer so it outlives the allocation it was read from.
fn copy_sid(sid: PSID) -> Vec<u8> {
    use windows_sys::Win32::Security::GetLengthSid;
    // SAFETY: callers pass a SID validated by the API that produced it.
    let length = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: `length` is the SID's own reported size.
    unsafe { std::slice::from_raw_parts(sid as *const u8, length) }.to_vec()
}

/// Materializes a well-known SID into an owned buffer.
fn well_known_sid(kind: i32) -> io::Result<Vec<u8>> {
    let mut size = 0u32;
    // SAFETY: size query; failure with a zero buffer is expected and inspected below.
    unsafe {
        CreateWellKnownSid(kind, ptr::null_mut(), ptr::null_mut(), &mut size);
    }
    let mut buffer = vec![0u8; size.max(1) as usize];
    // SAFETY: the buffer matches the size the API just asked for.
    let ok =
        unsafe { CreateWellKnownSid(kind, ptr::null_mut(), buffer.as_mut_ptr().cast(), &mut size) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buffer)
}

/// Compares two SIDs by value.
fn sid_equals(left: PSID, right: PSID) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    // SAFETY: both pointers are valid SIDs for the duration of the comparison.
    unsafe { EqualSid(left, right) != 0 }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

/// Renders a path for diagnostics without losing non-UTF-8 content.
#[allow(dead_code)]
fn display(path: &Path) -> OsString {
    OsString::from_wide(&path.as_os_str().encode_wide().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let target = wide(path.as_os_str());
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
