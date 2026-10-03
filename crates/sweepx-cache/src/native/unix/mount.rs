//! Linux mount evidence, with portable policy tests and OS-gated native observations.

use std::io;

/// Mount IDs are used only while native handles retain the mount, never as persistent tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity(u64);

impl Identity {
    pub(super) fn observe(mask: u32, id: u64) -> io::Result<Self> {
        // Linux UAPI STATX_MNT_ID. A zero-filled unsupported field is not mount evidence.
        require_fields(mask, 0x1000)?;
        Ok(Self(id))
    }

    pub(super) fn require_same(self, other: Self) -> io::Result<()> {
        if self != other {
            return Err(io::Error::other("cache object crossed a mount boundary"));
        }
        Ok(())
    }
}

fn require_fields(observed: u32, required: u32) -> io::Result<()> {
    if observed & required != required {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "statx omitted required cache metadata or mount evidence",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::ffi::CStr;
    use std::os::fd::RawFd;

    // Only fields actually consumed by accounting/admission are mandatory. Physical blocks,
    // birth time and unrelated ownership fields neither define this ledger nor prove safety.
    const ACCOUNTING_FIELDS: u32 = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_NLINK
        | libc::STATX_UID
        | libc::STATX_ATIME
        | libc::STATX_CTIME
        | libc::STATX_INO
        | libc::STATX_SIZE
        | libc::STATX_MNT_ID;

    fn query(fd: RawFd, name: &CStr, flags: i32, required: u32) -> io::Result<libc::statx> {
        let mut metadata = std::mem::MaybeUninit::<libc::statx>::zeroed();
        // SAFETY: live retained fd and NUL-terminated empty/one-component name; successful
        // statx initializes the output. No link following, payload open or display-path lookup.
        if unsafe { libc::statx(fd, name.as_ptr(), flags, required, metadata.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = unsafe { metadata.assume_init() };
        require_fields(metadata.stx_mask, required)?;
        Ok(metadata)
    }

    pub(crate) fn for_fd(fd: RawFd) -> io::Result<Identity> {
        let metadata = query(
            fd,
            c"",
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
        )?;
        Identity::observe(metadata.stx_mask, metadata.stx_mnt_id)
    }

    pub(crate) fn relative(fd: RawFd, name: &CStr) -> io::Result<(Identity, libc::statx)> {
        let metadata = query(
            fd,
            name,
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
            ACCOUNTING_FIELDS,
        )?;
        Ok((
            Identity::observe(metadata.stx_mask, metadata.stx_mnt_id)?,
            metadata,
        ))
    }
}

#[cfg(target_os = "linux")]
pub(super) use native::{for_fd, relative};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_mount_is_not_a_zero_identity() {
        for mask in [0, 0x7ff, 0x8000_0000] {
            assert_eq!(
                Identity::observe(mask, 0).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
        assert!(
            Identity::observe(0x1000, 0).is_ok(),
            "the returned mask defines evidence, not a guessed ID sentinel"
        );
    }

    #[test]
    fn same_device_and_inode_cannot_substitute_for_mount_identity() {
        let original = Identity::observe(0x1fff, 47).unwrap();
        let bind = Identity::observe(0x1fff, 48).unwrap();
        assert!(original.require_same(bind).is_err());
        original
            .require_same(Identity::observe(0x1000, 47).unwrap())
            .unwrap();
    }

    #[test]
    fn every_requested_field_needs_its_returned_bit() {
        let required = 0x135f;
        for bit in 0..32 {
            if required & (1 << bit) != 0 {
                assert!(require_fields(required & !(1 << bit), required).is_err());
            }
        }
        require_fields(required | 0x8000_0000, required).unwrap();
    }
}
