//! Metadata preflight retains authority and never opens/closes another database descriptor.
//! SQLite still uses its default pathname VFS; this is not an actual C-file binding proof.

use super::{AuditError, FileIdentity};
#[cfg(unix)]
use super::{DATABASE_FILE, LOCK_FILE};
use std::fs::File;
#[cfg(unix)]
use std::{
    io,
    path::{Path, PathBuf},
};
#[cfg(unix)]
use sweepx_cache::native::{Directory, StateFileMetadata};

#[derive(Debug)]
pub(super) struct Root {
    #[cfg(unix)]
    display: PathBuf,
    #[cfg(unix)]
    directory: Directory,
}

impl Root {
    #[cfg(unix)]
    pub(super) fn open(display: &Path) -> Result<Self, AuditError> {
        let directory = Directory::open(display, false)?;
        super::ensure_local_filesystem(&directory.directory_file()?)?;
        Ok(Self {
            display: display.to_path_buf(),
            directory,
        })
    }

    pub(super) fn binding(&self) -> Result<(), AuditError> {
        #[cfg(unix)]
        {
            let current =
                Directory::open(&self.display, false).map_err(|_| AuditError::StoreMismatch)?;
            if !self.directory.same_object(&current)? {
                return Err(AuditError::StoreMismatch);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        Err(AuditError::UnsupportedPlatform)
    }

    #[cfg(unix)]
    fn metadata(&self, name: &str) -> Result<StateFileMetadata, AuditError> {
        self.directory.state_metadata(name).map_err(|error| {
            if sweepx_cache::native::is_link_refusal(&error) {
                AuditError::SymlinkRejected(self.display.join(name).display().to_string())
            } else {
                AuditError::Io(error)
            }
        })
    }

    pub(super) fn identity(&self) -> Result<FileIdentity, AuditError> {
        #[cfg(unix)]
        {
            let metadata = self.metadata(DATABASE_FILE)?;
            Ok(FileIdentity {
                device: metadata.device,
                inode: metadata.inode,
            })
        }
        #[cfg(not(unix))]
        Err(AuditError::UnsupportedPlatform)
    }

    pub(super) fn length(&self, name: &str) -> Result<u64, AuditError> {
        #[cfg(unix)]
        match self.metadata(name) {
            Ok(metadata) => Ok(metadata.bytes),
            // Explicit absence alone is zero optional storage; denial/unsafe/provider remain errors.
            Err(AuditError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error),
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Err(AuditError::UnsupportedPlatform)
        }
    }

    pub(super) fn sidecars(&self) -> Result<(), AuditError> {
        for name in ["audit.db-wal", "audit.db-shm", "audit.db-journal"] {
            self.length(name)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(super) fn create_database(&self) -> Result<(), AuditError> {
        self.binding()?;
        // Exclusive creation must not reopen an unexpected existing DB inode: even a failed
        // creator closing that extra FD could release another same-process SQLite lock.
        let file = self.directory.create_state_file(DATABASE_FILE)?;
        file.sync_all()?;
        self.sync()
    }

    #[cfg(unix)]
    pub(super) fn sync(&self) -> Result<(), AuditError> {
        self.directory.directory_file()?.sync_all()?;
        Ok(())
    }

    pub(super) fn lock_filesystem(&self, lock: &File) -> Result<(), AuditError> {
        #[cfg(unix)]
        {
            // Duplicate a directory descriptor only; a same-inode data FD close releases
            // POSIX SQLite locks, so filesystem validation must not reopen audit.db.
            super::ensure_same_local_filesystem(lock, &self.directory.directory_file()?)?;
            let metadata = self.metadata(LOCK_FILE)?;
            let expected = super::lock_identity(lock, &self.display.join(LOCK_FILE))?;
            if metadata.device != expected.device || metadata.inode != expected.inode {
                return Err(AuditError::LockReplaced);
            }
            self.identity()?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = lock;
            Err(AuditError::UnsupportedPlatform)
        }
    }
}
