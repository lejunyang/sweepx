//! Native authority and accounting for the Linux journal's retained-descriptor SQLite VFS.

use super::{JournalError, ensure_local_filesystem};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use sweepx_cache::native::Directory;

#[derive(Debug)]
pub(super) struct Root {
    display: PathBuf,
    directory: Directory,
    // Retained alias for directory synchronization, never reopened through its display name.
    file: File,
}

impl Root {
    pub(super) fn open(display: &Path, create: bool) -> Result<Self, JournalError> {
        if !display.is_absolute() {
            return Err(JournalError::StateDirNotAbsolute);
        }
        let directory =
            Directory::open(display, create).map_err(|error| directory_error(display, error))?;
        Self::captured(directory, display)
    }

    pub(super) fn captured(directory: Directory, display: &Path) -> Result<Self, JournalError> {
        if !display.is_absolute() {
            return Err(JournalError::StateDirNotAbsolute);
        }
        let file = directory.directory_file()?;
        ensure_local_filesystem(&file)?;
        let root = Self {
            display: display.to_path_buf(),
            directory,
            file,
        };
        // Refuse a stale caller capture before creating lock/database names. This does not
        // make later relative unlink atomic with a non-cooperating namespace writer.
        root.binding()?;
        Ok(root)
    }

    pub(super) fn binding(&self) -> Result<(), JournalError> {
        // This is a rejection gate, never a new I/O authority. Both directory captures use
        // no-follow ancestry and mount evidence; a same-inode bind alias is not the same root.
        let current = Directory::open(&self.display, false)
            .map_err(|_| JournalError::StateIdentityChanged)?;
        if !self.directory.same_object(&current)? {
            return Err(JournalError::StateIdentityChanged);
        }
        Ok(())
    }

    pub(super) fn sync(&self) -> Result<(), JournalError> {
        // Both handles must still satisfy the admitted private/mount contract before flush.
        let _ = self.directory.directory_file()?;
        self.file.sync_all()?;
        Ok(())
    }

    pub(super) fn file(&self, name: &str, create: bool) -> Result<(File, bool), JournalError> {
        let (file, created) = self
            .directory
            .state_file(name, create)
            .map_err(|error| file_error(&self.display.join(name), error))?;
        ensure_local_filesystem(&file)?;
        if created {
            file.sync_all()?;
            self.file.sync_all()?;
        }
        Ok((file, created))
    }

    pub(super) fn length(&self, name: &str) -> Result<u64, JournalError> {
        // statx beneath the retained parent never closes a second database FD. POSIX locks
        // would otherwise be released even while SQLite still believes it owns them.
        match self.directory.metadata(name) {
            Ok(metadata) => Ok(metadata.bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(file_error(&self.display.join(name), error)),
        }
    }

    pub(super) fn contains(&self, name: &str, file: &File) -> Result<bool, JournalError> {
        self.directory
            .contains_file(name, file)
            .map_err(|error| file_error(&self.display.join(name), error))
    }
}

impl super::retained_vfs::Storage for Root {
    fn open(
        &self,
        name: super::retained_vfs::Name,
        create: bool,
        exclusive: bool,
    ) -> io::Result<File> {
        let (file, created) = self.file(name.text(), create).map_err(io::Error::other)?;
        if exclusive && !created {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "journal sidecar already exists",
            ));
        }
        Ok(file)
    }

    fn contains(&self, name: super::retained_vfs::Name, file: &File) -> io::Result<bool> {
        self.directory.contains_file(name.text(), file)
    }

    fn length(&self, name: super::retained_vfs::Name) -> io::Result<Option<u64>> {
        match self.directory.metadata(name.text()) {
            Ok(metadata) => Ok(Some(metadata.bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn remove(&self, name: super::retained_vfs::Name, expected: Option<&File>) -> io::Result<()> {
        // Metadata first preserves explicit absence and native private/mount/type refusal.
        self.directory.metadata(name.text())?;
        if let Some(file) = expected
            && !self.directory.contains_file(name.text(), file)?
        {
            return Err(io::Error::other("journal sidecar changed before removal"));
        }
        // Linux unlink has no identity-conditional form: the last check-to-unlink window
        // remains explicit. Authority is the retained parent, never a SQLite pathname.
        self.directory.remove(name.text())
    }

    fn sync(&self) -> io::Result<()> {
        Root::sync(self).map_err(io::Error::other)
    }
}

fn directory_error(path: &Path, error: io::Error) -> JournalError {
    if sweepx_cache::native::is_link_refusal(&error) {
        return JournalError::SymlinkRejected(path.display().to_string());
    }
    match error.kind() {
        io::ErrorKind::NotFound => JournalError::StateNotFound,
        io::ErrorKind::InvalidInput | io::ErrorKind::NotADirectory => {
            JournalError::UnsafeStateDir(path.display().to_string())
        }
        io::ErrorKind::Other | io::ErrorKind::PermissionDenied => {
            JournalError::StateDirNotPrivate(path.display().to_string())
        }
        _ => JournalError::Io(error),
    }
}

fn file_error(path: &Path, error: io::Error) -> JournalError {
    if sweepx_cache::native::is_link_refusal(&error) {
        return JournalError::SymlinkRejected(path.display().to_string());
    }
    match error.kind() {
        io::ErrorKind::NotFound => JournalError::StateNotFound,
        io::ErrorKind::Other | io::ErrorKind::PermissionDenied | io::ErrorKind::NotADirectory => {
            JournalError::UnsafeStateFile(path.display().to_string())
        }
        _ => JournalError::Io(error),
    }
}
