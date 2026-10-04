//! Native audit authority and synchronous retained SQLite connection intervals.
//! Provider policy includes SQL, mapped index access and close before returning capabilities.

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

    pub(super) fn with_connection<T>(
        self: &std::sync::Arc<Self>,
        expected: &FileIdentity,
        operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T, AuditError>,
    ) -> Result<T, AuditError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let result = sweepx_cache::native::with_io_policy(|| {
                use crate::retained_vfs::{FileLimits, Registered, Storage, WalMode};
                self.binding()?;
                self.require_identity(expected)?;
                self.sidecars()?;
                super::check_native_size_budget(self, true)?;
                #[cfg(all(test, target_os = "macos"))]
                observe_policy(1);
                #[cfg(test)]
                BEFORE_DATABASE_OPEN.with(|hook| {
                    let callback = hook.borrow_mut().take();
                    if let Some(callback) = callback {
                        callback();
                    }
                });
                let (database, _) = self.directory.state_file(super::DATABASE_FILE, false)?;
                // Validate the actual opened description before any SQLite configuration/read.
                // A namespace swap after metadata admission must not open a different DB object.
                use std::os::unix::fs::MetadataExt;
                let observed = database.metadata()?;
                if observed.dev() != expected.device || observed.ino() != expected.inode {
                    return Err(AuditError::StoreMismatch);
                }
                let vfs = Registered::new(
                    std::sync::Arc::clone(self) as std::sync::Arc<dyn Storage>,
                    database,
                    FileLimits {
                        database_bytes: super::MAX_DATABASE_BYTES,
                        wal_bytes: super::MAX_WAL_BYTES,
                        rollback_bytes: super::MAX_TOTAL_DATABASE_BYTES,
                        shm_bytes: 1024 * 1024,
                        total_bytes: super::MAX_TOTAL_DATABASE_BYTES,
                    },
                    WalMode::Shared,
                )?;
                let mut connection = super::open_connection(&vfs)?;
                self.verify_connection(&vfs, &connection, expected)?;
                #[cfg(all(test, target_os = "macos"))]
                observe_policy(64);
                let result = operation(&mut connection);
                // Explicit close runs checkpoint/index cleanup under the issuing thread policy.
                // Even a failed close's returned Connection is dropped before restoration.
                let closed = connection
                    .close()
                    .map_err(|(_, error)| AuditError::Database(error));
                #[cfg(all(test, target_os = "macos"))]
                observe_policy(128);
                let bound = self.binding().and_then(|()| {
                    self.require_identity(expected)?;
                    if !self
                        .directory
                        .contains_file(super::DATABASE_FILE, vfs.database())?
                    {
                        return Err(AuditError::StoreMismatch);
                    }
                    self.sidecars()?;
                    super::check_native_size_budget(self, true)
                });
                if result.is_ok() {
                    closed?;
                    bound?;
                }
                result
            });
            #[cfg(test)]
            if result.is_ok() && REJECT_SQL_RESULT_ONCE.with(|flag| flag.replace(false)) {
                // Phase refusal after actual checked restoration, not a failing kernel setter.
                // Exercise capability publication without leaving the OS thread altered.
                return Err(AuditError::Io(io::Error::other(
                    "injected audit interval result refusal",
                )));
            }
            result
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (expected, operation);
            Err(AuditError::UnsupportedPlatform)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn require_identity(&self, expected: &FileIdentity) -> Result<(), AuditError> {
        if &self.identity()? != expected {
            return Err(AuditError::StoreMismatch);
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn verify_connection(
        &self,
        vfs: &crate::retained_vfs::Registered,
        connection: &rusqlite::Connection,
        expected: &FileIdentity,
    ) -> Result<(), AuditError> {
        self.binding()?;
        self.require_identity(expected)?;
        if !vfs.owns_connection(connection)? {
            return Err(AuditError::StoreMismatch);
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl crate::retained_vfs::Storage for Root {
    fn open(
        &self,
        name: crate::retained_vfs::Name,
        create: bool,
        exclusive: bool,
    ) -> io::Result<File> {
        #[cfg(all(test, target_os = "macos"))]
        observe_policy(2);
        let file = if exclusive {
            if !create {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exclusive audit creation requires create",
                ));
            }
            self.directory.create_state_file(physical_name(name))?
        } else {
            self.directory.state_file(physical_name(name), create)?.0
        };
        super::ensure_local_filesystem(&file).map_err(io::Error::other)?;
        Ok(file)
    }
    fn contains(&self, name: crate::retained_vfs::Name, file: &File) -> io::Result<bool> {
        #[cfg(all(test, target_os = "macos"))]
        observe_policy(4);
        self.directory.contains_file(physical_name(name), file)
    }
    fn length(&self, name: crate::retained_vfs::Name) -> io::Result<Option<u64>> {
        #[cfg(all(test, target_os = "macos"))]
        observe_policy(8);
        match self.directory.state_metadata(physical_name(name)) {
            Ok(metadata) => Ok(Some(metadata.bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn remove(&self, name: crate::retained_vfs::Name, expected: Option<&File>) -> io::Result<()> {
        #[cfg(all(test, target_os = "macos"))]
        observe_policy(16);
        self.directory.state_metadata(physical_name(name))?;
        if let Some(file) = expected
            && !self.directory.contains_file(physical_name(name), file)?
        {
            return Err(io::Error::other("audit sidecar changed before removal"));
        }
        self.directory.remove(physical_name(name))
    }
    fn sync(&self) -> io::Result<()> {
        #[cfg(all(test, target_os = "macos"))]
        observe_policy(32);
        self.directory.directory_file()?.sync_all()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn physical_name(name: crate::retained_vfs::Name) -> &'static str {
    use crate::retained_vfs::Name;
    match name {
        Name::Database => "audit.db",
        Name::Wal => "audit.db-wal",
        Name::Rollback => "audit.db-journal",
        Name::Shm => "audit.db-shm",
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
std::thread_local! {
    pub(super) static REJECT_SQL_RESULT_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static BEFORE_DATABASE_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(all(test, target_os = "macos"))]
std::thread_local! {
    // Fixed bitmap rather than retaining every potentially numerous SQLite callback.
    pub(super) static POLICY_PROBE: std::cell::Cell<Option<(u32, bool)>> = const { std::cell::Cell::new(None) };
}
#[cfg(all(test, target_os = "macos"))]
pub(super) fn current_policy() -> i32 {
    unsafe extern "C" {
        fn getiopolicy_np(kind: i32, scope: i32) -> i32;
    }
    // Independent public Darwin ABI query, not derived from the guard's fields.
    unsafe { getiopolicy_np(3, 1) }
}
#[cfg(all(test, target_os = "macos"))]
fn observe_policy(bit: u32) {
    POLICY_PROBE.with(|probe| {
        if let Some((seen, failed)) = probe.get() {
            probe.set(Some((seen | bit, failed || current_policy() != 1)));
        }
    });
}
