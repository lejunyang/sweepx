//! Normal WAL index with the Unix SQLite lock-byte protocol and bounded stable mappings.
//! Locks belong to each open description; never downgrade to process-wide locks in production.
//! SQLite may access mapped pages between callbacks: provider policy must cover the complete
//! calling SQL interval, including close/unmap, rather than just the mmap syscall.

use super::*;

// Independent SQLite Unix protocol: 8 WAL lock bytes at 120, dead-man switch at 128.
const BASE: libc::off_t = 120;
const DMS: libc::off_t = 128;
const REGION: usize = 32768;

struct Mapping {
    pointer: *mut c_void,
    bytes: usize,
}
impl Mapping {
    fn release(mut self) -> io::Result<()> {
        // SAFETY: exact owned mapping, no remaining SQLite users after xShmUnmap.
        if unsafe { libc::munmap(self.pointer, self.bytes) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.pointer = ptr::null_mut();
        Ok(())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this owns one live, exact mmap interval; SQLite has finished using it.
        if !self.pointer.is_null() {
            unsafe { libc::munmap(self.pointer, self.bytes) };
        }
    }
}

pub(super) struct SharedMemory {
    file: NativeFile,
    mapping: Option<Mapping>,
}

fn conflict(file: &File, start: libc::off_t, len: libc::off_t) -> io::Result<libc::c_short> {
    // SAFETY: initialized flock for a live descriptor; OFD query includes same-process locks.
    let mut query: libc::flock = unsafe { std::mem::zeroed() };
    query.l_type = libc::F_WRLCK as libc::c_short;
    query.l_whence = libc::SEEK_SET as libc::c_short;
    query.l_start = start;
    query.l_len = len;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let command = libc::F_OFD_GETLK;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let command = libc::F_GETLK;
    if unsafe { libc::fcntl(file.as_raw_fd(), command, &mut query) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(query.l_type)
    }
}

impl SharedMemory {
    fn open(context: &Context) -> Result<Self, c_int> {
        context.growth(Name::Shm, 3)?;
        let file = context
            .storage
            .open(Name::Shm, true, false)
            .map_err(|_| ffi::SQLITE_IOERR_SHMOPEN)?;
        match conflict(&file, DMS, 1).map_err(|_| ffi::SQLITE_IOERR_SHMLOCK)? as c_int {
            kind if kind == libc::F_UNLCK as c_int => {
                record_lock(&file, libc::F_WRLCK, DMS, 1)
                    .map_err(|error| lock_result(Err(error)))?;
                // The first live client invalidates old index state while holding DMS
                // exclusively. Only then can readers attach; an initializer race returns BUSY.
                if file.set_len(3).is_err() {
                    let _ = record_lock(&file, libc::F_UNLCK, DMS, 1);
                    return Err(ffi::SQLITE_IOERR_SHMSIZE);
                }
            }
            kind if kind == libc::F_RDLCK as c_int => {}
            _ => return Err(ffi::SQLITE_BUSY),
        }
        record_lock(&file, libc::F_RDLCK, DMS, 1).map_err(|error| lock_result(Err(error)))?;
        Ok(Self {
            file,
            mapping: None,
        })
    }

    fn valid(&self, context: &Context) -> Result<(), c_int> {
        if context
            .storage
            .contains(Name::Shm, &self.file)
            .map_err(|_| ffi::SQLITE_IOERR_SHMOPEN)?
        {
            Ok(())
        } else {
            Err(ffi::SQLITE_IOERR_SHMOPEN)
        }
    }

    pub(super) fn finish(mut self, context: &Context, delete: bool) -> Result<(), c_int> {
        if let Some(mapping) = self.mapping.take() {
            mapping.release().map_err(|_| ffi::SQLITE_IOERR_SHMMAP)?;
        }
        // Unlock only this description's eight WAL slots. Other readers' OFD/POSIX locks
        // remain intact; no process-global registry or global syscall override is involved.
        let slots = record_lock(&self.file, libc::F_UNLCK, BASE, 8);
        let dead = record_lock(&self.file, libc::F_UNLCK, DMS, 1);
        slots.and(dead).map_err(|_| ffi::SQLITE_IOERR_SHMLOCK)?;
        if delete {
            match record_lock(&self.file, libc::F_WRLCK, DMS, 1) {
                Ok(()) => {}
                Err(error)
                    if [Some(libc::EAGAIN), Some(libc::EACCES)].contains(&error.raw_os_error()) =>
                {
                    return Ok(());
                }
                Err(_) => return Err(ffi::SQLITE_IOERR_SHMLOCK),
            }
            // Refuse stale native binding before unlink. Linux/macOS still have a final
            // noncooperating check-to-unlink window; this is never target deletion authority.
            let result = context
                .authority()
                .map_err(|_| ffi::SQLITE_IOERR_SHMOPEN)
                .and_then(|()| self.valid(context))
                .and_then(|()| {
                    context
                        .storage
                        .remove(Name::Shm, Some(&self.file))
                        .map_err(|_| ffi::SQLITE_IOERR_DELETE)
                });
            let unlocked = record_lock(&self.file, libc::F_UNLCK, DMS, 1)
                .map_err(|_| ffi::SQLITE_IOERR_SHMLOCK);
            result.and(unlocked)?;
        }
        Ok(())
    }
}

pub(super) unsafe extern "C" fn map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    page_bytes: c_int,
    extend: c_int,
    out: *mut *mut c_void,
) -> c_int {
    boundary(ffi::SQLITE_IOERR_SHMMAP, || {
        if out.is_null() {
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        // SAFETY: SQLite supplies writable pointer output; absence always initializes it.
        unsafe {
            *out = ptr::null_mut();
        }
        let result = (|| -> Result<(), c_int> {
            let page = usize::try_from(page).map_err(|_| ffi::SQLITE_IOERR_SHMMAP)?;
            if page_bytes != REGION as c_int {
                return Err(ffi::SQLITE_IOERR_SHMMAP);
            }
            let state = unsafe { state(file) };
            if state.name != Name::Database || state.context.mode != WalMode::Shared {
                return Err(ffi::SQLITE_IOERR_SHMMAP);
            }
            state.valid().map_err(|_| ffi::SQLITE_IOERR_SHMMAP)?;
            let end = page
                .checked_add(1)
                .and_then(|p| p.checked_mul(REGION))
                .ok_or(ffi::SQLITE_FULL)?;
            if end as u64 > state.context.limits.shm_bytes {
                return Err(ffi::SQLITE_FULL);
            }
            if state.shm.is_none() {
                state.shm = Some(SharedMemory::open(&state.context)?);
            }
            let memory = state.shm.as_mut().ok_or(ffi::SQLITE_IOERR_SHMMAP)?;
            memory.valid(&state.context)?;
            let len = memory
                .file
                .metadata()
                .map_err(|_| ffi::SQLITE_IOERR_SHMSIZE)?
                .len();
            if len < end as u64 {
                if extend == 0 {
                    return Ok(());
                }
                // Back newly extended OS pages before returning shared memory. Charge actual
                // rounded growth, including hosts whose pages exceed the 32-KiB index region.
                // SAFETY: sysconf is thread-safe and takes no pointer arguments.
                let native_page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
                    .map_err(|_| ffi::SQLITE_IOERR_SHMSIZE)?;
                if !native_page.is_power_of_two() || native_page > 1024 * 1024 {
                    return Err(ffi::SQLITE_IOERR_SHMSIZE);
                }
                let backed = end.div_ceil(native_page) * native_page;
                state.context.growth(Name::Shm, backed as u64)?;
                memory
                    .file
                    .set_len(backed as u64)
                    .map_err(|_| ffi::SQLITE_IOERR_SHMSIZE)?;
                let mut byte =
                    len / native_page as u64 * native_page as u64 + native_page as u64 - 1;
                while byte < backed as u64 {
                    if memory
                        .file
                        .write_at(&[0], byte)
                        .map_err(|_| ffi::SQLITE_IOERR_SHMSIZE)?
                        != 1
                    {
                        return Err(ffi::SQLITE_IOERR_SHMSIZE);
                    }
                    byte += native_page as u64;
                }
            }
            if memory.mapping.is_none() {
                let bytes = state.context.limits.shm_bytes as usize;
                // One stable mapping reserves only the declared capacity (at most 1 MiB).
                // Pages beyond current EOF are not returned until checked file extension.
                // SAFETY: live read/write FD, positive bounded mapping, fixed zero offset.
                let pointer = unsafe {
                    libc::mmap(
                        ptr::null_mut(),
                        bytes,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        memory.file.as_raw_fd(),
                        0,
                    )
                };
                if pointer == libc::MAP_FAILED {
                    return Err(ffi::SQLITE_IOERR_SHMMAP);
                }
                if pointer.is_null() {
                    // Address zero cannot represent SQLite's required nonnull mapped page.
                    unsafe { libc::munmap(pointer, bytes) };
                    return Err(ffi::SQLITE_IOERR_SHMMAP);
                }
                memory.mapping = Some(Mapping { pointer, bytes });
            }
            let mapping = memory.mapping.as_ref().ok_or(ffi::SQLITE_IOERR_SHMMAP)?;
            // SAFETY: admitted region end lies within stable mapping and current file extent.
            unsafe {
                *out = mapping.pointer.cast::<u8>().add(page * REGION).cast();
            }
            Ok(())
        })();
        result.map_or_else(|code| code, |()| ffi::SQLITE_OK)
    })
}

pub(super) unsafe extern "C" fn lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    boundary(ffi::SQLITE_IOERR_SHMLOCK, || {
        let state = unsafe { state(file) };
        if state.valid().is_err()
            || offset < 0
            || count < 1
            || offset.checked_add(count).is_none_or(|end| end > 8)
        {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        let Some(memory) = state.shm.as_ref() else {
            return ffi::SQLITE_IOERR_SHMLOCK;
        };
        if memory.valid(&state.context).is_err() {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        let kind = match flags {
            f if f == ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_SHARED
                || f == ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_EXCLUSIVE =>
            {
                libc::F_UNLCK
            }
            f if f == ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_SHARED && count == 1 => libc::F_RDLCK,
            f if f == ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_EXCLUSIVE => libc::F_WRLCK,
            _ => {
                return ffi::SQLITE_IOERR_SHMLOCK;
            }
        };
        let result = record_lock(
            &memory.file,
            kind,
            BASE + offset as libc::off_t,
            count as libc::off_t,
        );
        result.map_or_else(|error| lock_result(Err(error)), |()| ffi::SQLITE_OK)
    })
}

pub(super) unsafe extern "C" fn barrier(_file: *mut ffi::sqlite3_file) {
    // SQLite owns the index access protocol; this supplies cross-thread/process ordering
    // for the shared mapping without reading or writing cached index bytes ourselves.
    std::sync::atomic::fence(Ordering::SeqCst);
}

pub(super) unsafe extern "C" fn unmap(file: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    boundary(ffi::SQLITE_IOERR_SHMMAP, || {
        let state = unsafe { state(file) };
        let Some(memory) = state.shm.take() else {
            return ffi::SQLITE_OK;
        };
        memory
            .finish(&state.context, delete != 0)
            .map_or_else(|code| code, |()| ffi::SQLITE_OK)
    })
}
