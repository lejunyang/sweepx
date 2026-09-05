//! Reads a file's native identity from the live filesystem, by path.
//!
//! This exists so a destructive action can re-establish *what* it is about to act on immediately
//! before acting. A display path is a name, not an authority: between the moment a scan recorded a
//! row and the moment a user confirms it, the name can be pointed at something else — a rename, a
//! junction swap, a recreated directory. Comparing the identity behind the name against the one the
//! scan recorded is what turns "the path still resolves" into "it is still the same object".
//!
//! `std::os::windows::fs::MetadataExt::file_index` and `volume_serial_number` would answer this
//! directly, but both are still unstable (`windows_by_handle`), so the identity is read from
//! `FILE_ID_INFO` instead. That is also the same source the scanner already uses, which keeps the
//! two sides of the comparison on one definition of identity rather than two that merely look alike.

use std::io;
use std::mem;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::path::Path;

use sweepx_platform::EntryIdentity;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
};

/// Opens a directory as well as a file. Without it, opening a directory fails outright.
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// Opens the link itself rather than its target.
///
/// Traversal here would read the identity of whatever the link points at, so a junction swapped in
/// after the scan would answer with a legitimate-looking identity belonging to a different object —
/// exactly the substitution this check exists to catch.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Reads the live native identity of whatever `path` currently names.
///
/// Returns `Ok(None)` when the path no longer resolves, which is a legitimate outcome rather than an
/// error: something that is already gone cannot be acted on, and the caller decides what that means.
/// Any other failure is returned as an error, because an identity that could not be read must never
/// be treated as one that matched.
pub fn read_live_identity(path: &Path) -> io::Result<Option<EntryIdentity>> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let identity = identity_from_handle(file.as_raw_handle())?;
    Ok(Some(identity))
}

/// Reads `FILE_ID_INFO` from an open handle and converts it to the scanner's identity type.
fn identity_from_handle(handle: RawHandle) -> io::Result<EntryIdentity> {
    let mut info = FILE_ID_INFO {
        VolumeSerialNumber: 0,
        FileId: unsafe { mem::zeroed() },
    };
    // SAFETY: `handle` is a live handle owned by the caller's `File` for the duration of this call,
    // and the buffer is a correctly sized `FILE_ID_INFO` matching the requested class.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle as HANDLE,
            FileIdInfo,
            (&raw mut info).cast(),
            u32::try_from(mem::size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO size fits u32"),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(EntryIdentity::from_windows_file_id(
        info.VolumeSerialNumber,
        info.FileId.Identifier,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_path_is_absent_rather_than_an_error() {
        let missing = std::env::temp_dir().join("sweepx-identity-does-not-exist-4f2a9c");
        let _ = std::fs::remove_dir_all(&missing);
        assert_eq!(
            read_live_identity(&missing).expect("a missing path is not an error"),
            None
        );
    }

    #[test]
    fn a_directory_has_a_readable_identity_that_is_stable_across_reads() {
        let dir = std::env::temp_dir().join(format!("sweepx-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        let first = read_live_identity(&dir)
            .expect("readable")
            .expect("present");
        let second = read_live_identity(&dir)
            .expect("readable")
            .expect("present");
        assert_eq!(first, second, "identity is stable for an unchanged object");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recreating_a_directory_at_the_same_path_changes_its_identity() {
        // This is the substitution the check exists to catch: the path is unchanged and still
        // resolves, but it names a different object than the one that was scanned.
        let dir = std::env::temp_dir().join(format!("sweepx-identity-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let before = read_live_identity(&dir)
            .expect("readable")
            .expect("present");

        std::fs::remove_dir_all(&dir).expect("removable");
        std::fs::create_dir_all(&dir).expect("recreatable");
        let after = read_live_identity(&dir)
            .expect("readable")
            .expect("present");

        assert_ne!(
            before, after,
            "a recreated directory must not pass as the scanned one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
