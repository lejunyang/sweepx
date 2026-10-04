//! The I/O admission lease follows the actual file owner, including foreign SQLite lifetimes.

use super::authority::{Lease, Owner};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Deref;

/// An owned storage file charged to the shared 256 native I/O handle allowance until close.
/// Native factories reserve before opening or creating. `admit` accepts an existing file;
/// neither this wrapper nor its borrowed `File` establishes filesystem or deletion authority.
/// Borrowed handles must not be duplicated outside `try_clone` for accounted storage I/O.
/// There is deliberately no transfer back to an uncharged owned `File` or raw handle.
#[derive(Debug)]
pub struct NativeFile {
    owner: Owner<File>,
}

impl NativeFile {
    pub(super) fn new(file: File, lease: Lease) -> Self {
        Self {
            owner: Owner::new(file, lease),
        }
    }

    /// Transfers an already open file into admission; on refusal the transferred file closes.
    /// This does not validate identity, permissions, mount boundaries or provider behavior.
    pub fn admit(file: File) -> io::Result<Self> {
        Ok(Self::new(file, Lease::acquire_io()?))
    }

    /// Reserves before duplicating the same native open file description.
    /// Sharing an `Arc<NativeFile>` instead retains one charge until its final owner closes.
    pub fn try_clone(&self) -> io::Result<Self> {
        let lease = Lease::acquire_io()?;
        Ok(Self::new(self.owner.try_clone()?, lease))
    }
}

impl Deref for NativeFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.owner
    }
}
impl Read for NativeFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        (&**self).read(bytes)
    }
}
impl Write for NativeFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        (&**self).write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&**self).flush()
    }
}
impl Seek for NativeFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        (&**self).seek(position)
    }
}
#[cfg(unix)]
impl std::os::fd::AsRawFd for NativeFile {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.owner.as_raw_fd()
    }
}
#[cfg(unix)]
impl std::os::fd::AsFd for NativeFile {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.owner.as_fd()
    }
}
#[cfg(windows)]
impl std::os::windows::io::AsRawHandle for NativeFile {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.owner.as_raw_handle()
    }
}
#[cfg(windows)]
impl std::os::windows::io::AsHandle for NativeFile {
    fn as_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.owner.as_handle()
    }
}
