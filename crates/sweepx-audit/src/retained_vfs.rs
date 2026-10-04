//! Process-lifetime SQLite VFS with bounded namespace leases and retained data descriptors.
//!
//! Exclusive mode has no shared-memory methods. Shared mode provides a bounded Unix WAL
//! index with OFD locks on Linux/macOS. Owners supply native authority and the complete
//! synchronous provider-policy interval, including mapped-page access and close.
//! Controlled fixtures exercise bundled SQLite separately from native mount admission.
//! Default POSIX VFS interoperability is qualified across independent processes only:
//! closing custom descriptors can release a builtin client's same-process POSIX locks.
//! Inherited SQLite connections must not be used after fork. Retirement rejects subsequent
//! file I/O; it cannot revoke data already loaded into a foreign connection's SQLite cache.

mod shm;
#[cfg(test)]
mod tests;

use rusqlite::{Connection, ffi};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

const IO_LIMIT: usize = 1024 * 1024;
// SQLite's published lock-byte protocol, not a filesystem allocation/sector claim.
const PENDING_BYTE: libc::off_t = 0x4000_0000;
const RESERVED_BYTE: libc::off_t = PENDING_BYTE + 1;
const SHARED_FIRST: libc::off_t = PENDING_BYTE + 2;
const SHARED_SIZE: libc::off_t = 510;

/// Caller-owned encoded-length policy checked at actual I/O boundaries.
#[derive(Debug, Clone, Copy)]
pub struct FileLimits {
    /// Maximum main database length.
    pub database_bytes: u64,
    /// Maximum WAL length.
    pub wal_bytes: u64,
    /// Maximum rollback-journal length.
    pub rollback_bytes: u64,
    /// Maximum SHM length; shared mode additionally caps mapping capacity at one MiB.
    pub shm_bytes: u64,
    /// Maximum sum of all four file lengths, including legacy sidecars.
    pub total_bytes: u64,
}
impl FileLimits {
    fn validate(self) -> io::Result<()> {
        if [
            self.database_bytes,
            self.wal_bytes,
            self.rollback_bytes,
            self.shm_bytes,
            self.total_bytes,
        ]
        .into_iter()
        .any(|n| n == 0 || n > i64::MAX as u64)
        {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid retained SQLite length limits",
            ))
        } else {
            Ok(())
        }
    }
}

/// WAL-index strategy; exclusive mode retains its original version-one I/O contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalMode {
    /// Caller configures EXCLUSIVE before WAL access; SHM remains accounting-only.
    Exclusive,
    /// Normal WAL readers/writers use a bounded, descriptor-bound shared-memory index.
    Shared,
}

/// Fixed VFS token names, mapped by Storage to retained native names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Name {
    /// Main database.
    Database,
    /// Write-ahead log.
    Wal,
    /// Rollback journal.
    Rollback,
    /// WAL-index file; exclusive mode only accounts its legacy length.
    Shm,
}

impl Name {
    /// Basename in the ephemeral VFS namespace, never a host pathname.
    pub fn text(self) -> &'static str {
        match self {
            Self::Database => "state.db",
            Self::Wal => "state.db-wal",
            Self::Rollback => "state.db-journal",
            Self::Shm => "state.db-shm",
        }
    }

    fn limit(self, limits: FileLimits) -> u64 {
        match self {
            Self::Database => limits.database_bytes,
            Self::Wal => limits.wal_bytes,
            Self::Rollback => limits.rollback_bytes,
            Self::Shm => limits.shm_bytes,
        }
    }

    // SAFETY contract at every caller: SQLite supplies a valid NUL-terminated filename.
    // We examine at most our fixed filename allowance, not an unbounded CStr scan.
    unsafe fn request(raw: *const c_char) -> Option<(u64, Self)> {
        if raw.is_null() {
            return None;
        }
        let mut bytes = [0_u8; 64];
        for len in 0..bytes.len() {
            let byte = unsafe { raw.add(len).read() } as u8;
            if byte == 0 {
                let input = bytes[..len].strip_prefix(b"/")?;
                let split = input.iter().position(|b| *b == b'/')?;
                let digits = &input[..split];
                if digits.is_empty() || digits.len() > 20 || digits[0] == b'0' {
                    return None;
                }
                let key = digits.iter().try_fold(0_u64, |n, byte| {
                    if !byte.is_ascii_digit() {
                        return None;
                    }
                    n.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
                })?;
                let name = match &input[split + 1..] {
                    b"state.db" => Self::Database,
                    b"state.db-wal" => Self::Wal,
                    b"state.db-journal" => Self::Rollback,
                    b"state.db-shm" => Self::Shm,
                    _ => return None,
                };
                return Some((key, name));
            }
            bytes[len] = byte;
        }
        None
    }
}

/// Native authority supplied by the owner; no callback accepts an execution pathname.
/// Provider policy must cover the complete SQL interval, including mapped-page accesses.
pub trait Storage: Send + Sync {
    /// Opens only an admitted relative file; requested exclusive creation must not reopen existing data.
    fn open(&self, name: Name, create: bool, exclusive: bool) -> io::Result<File>;
    /// Revalidates private/native relative binding without reopening another data descriptor.
    fn contains(&self, name: Name, file: &File) -> io::Result<bool>;
    /// Returns exact logical length or explicit absence; uncertainty remains an error.
    fn length(&self, name: Name) -> io::Result<Option<u64>>;
    /// Removes a checked sidecar via retained authority; final unlink races remain explicit.
    fn remove(&self, name: Name, expected: Option<&File>) -> io::Result<()>;
    /// Requests retained-parent synchronization, without a power-loss claim.
    fn sync(&self) -> io::Result<()>;
}

struct Context {
    storage: Arc<dyn Storage>,
    limits: FileLimits,
    mode: WalMode,
    database: Arc<File>,
    claimed: AtomicBool,
    // Only two allowed auxiliary files; keep closed sidecar evidence until deletion/reopen.
    sidecars: Mutex<[Option<Arc<File>>; 2]>,
    live: AtomicBool,
    _reservation: Reservation,
}

impl Context {
    fn authority(&self) -> io::Result<()> {
        if !self.live.load(Ordering::Acquire) {
            return Err(io::Error::other("retired journal namespace"));
        }
        if self.storage.contains(Name::Database, &self.database)? {
            Ok(())
        } else {
            Err(io::Error::other(
                "retained journal database binding changed",
            ))
        }
    }

    fn sidecar(&self, name: Name, create: bool, exclusive: bool) -> io::Result<Arc<File>> {
        let index = match name {
            Name::Wal => 0,
            Name::Rollback => 1,
            Name::Database | Name::Shm => return Err(io::Error::other("not a journal sidecar")),
        };
        let mut slots = self
            .sidecars
            .lock()
            .map_err(|_| io::Error::other("sidecar lock poisoned"))?;
        if let Some(file) = &slots[index] {
            if exclusive {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "sidecar already exists",
                ));
            }
            // Refuse a second live SQLite file object; reusing a closed sidecar uses its same
            // retained descriptor, so closing another descriptor cannot disturb record locks.
            if Arc::strong_count(file) != 1 {
                return Err(io::Error::other("sidecar already open"));
            }
            if self.storage.contains(name, file)? {
                return Ok(Arc::clone(file));
            }
            return Err(io::Error::other("closed sidecar binding changed"));
        }
        let file = Arc::new(self.storage.open(name, create, exclusive)?);
        slots[index] = Some(Arc::clone(&file));
        Ok(file)
    }

    fn growth(&self, name: Name, end: u64) -> Result<(), c_int> {
        if end > name.limit(self.limits) {
            return Err(ffi::SQLITE_FULL);
        }
        let mut total = 0_u64;
        for item in [Name::Database, Name::Wal, Name::Rollback, Name::Shm] {
            let bytes = self
                .storage
                .length(item)
                .map_err(|_| ffi::SQLITE_IOERR_FSTAT)?
                .unwrap_or(0);
            let bytes = if item == name { bytes.max(end) } else { bytes };
            if bytes > item.limit(self.limits) {
                return Err(ffi::SQLITE_FULL);
            }
            total = total.checked_add(bytes).ok_or(ffi::SQLITE_FULL)?;
        }
        if total > self.limits.total_bytes {
            Err(ffi::SQLITE_FULL)
        } else {
            Ok(())
        }
    }
}

const VFS_NAME: &CStr = c"sweepx-retained-state-v1";
const MAX_CONTEXTS: usize = 64;

struct Registry {
    // Process-lifetime VFS allocation: even a foreign connection that races an owner's
    // retirement can never retain a dangling sqlite3_vfs pointer.
    _vfs: Box<ffi::sqlite3_vfs>,
    defaults: *mut ffi::sqlite3_vfs,
    contexts: Mutex<BTreeMap<u64, Weak<Context>>>,
    active: AtomicUsize,
}

// SAFETY: these stable VFS allocations live for the process, linkage is SQLite-mutex-owned,
// and only thread-safe non-file builtin callbacks are delegated. The context ledger has its
// own mutex; callbacks never mutate/read mutable registration linkage from Rust.
unsafe impl Send for Registry {}
unsafe impl Sync for Registry {}

impl Registry {
    #[cfg(test)]
    fn raw(&self) -> *mut ffi::sqlite3_vfs {
        (&*self._vfs as *const ffi::sqlite3_vfs).cast_mut()
    }
    fn lookup(&self, key: u64) -> Option<Arc<Context>> {
        self.contexts.lock().ok()?.get(&key)?.upgrade()
    }
}

struct Reservation {
    registry: &'static Registry,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.registry.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn registry() -> io::Result<&'static Registry> {
    static REGISTRY: OnceLock<Result<Registry, &'static str>> = OnceLock::new();
    match REGISTRY.get_or_init(|| {
        // SAFETY: builtin initialization/lookup and registration use SQLite's registry mutex.
        if unsafe { ffi::sqlite3_initialize() } != ffi::SQLITE_OK {
            return Err("SQLite initialization failed");
        }
        let defaults = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
        if defaults.is_null() {
            return Err("builtin Unix VFS unavailable");
        }
        if !unsafe { ffi::sqlite3_vfs_find(VFS_NAME.as_ptr()) }.is_null() {
            return Err("journal VFS name already registered");
        }
        // SAFETY: optional pointers are zero; every required version-one method is supplied.
        let mut vfs: Box<ffi::sqlite3_vfs> = Box::new(unsafe { std::mem::zeroed() });
        vfs.iVersion = 1;
        vfs.szOsFile = std::mem::size_of::<Slot>() as c_int;
        vfs.mxPathname = 64;
        vfs.zName = VFS_NAME.as_ptr();
        vfs.xOpen = Some(open);
        vfs.xDelete = Some(delete);
        vfs.xAccess = Some(access);
        vfs.xFullPathname = Some(full_path);
        vfs.xDlOpen = Some(dl_open);
        vfs.xDlError = Some(dl_error);
        vfs.xDlSym = Some(dl_sym);
        vfs.xDlClose = Some(dl_close);
        vfs.xRandomness = Some(randomness);
        vfs.xSleep = Some(sleep);
        vfs.xCurrentTime = Some(current_time);
        vfs.xGetLastError = Some(last_error);
        if unsafe { ffi::sqlite3_vfs_register(&mut *vfs, 0) } != ffi::SQLITE_OK {
            return Err("journal VFS registration failed");
        }
        Ok(Registry {
            _vfs: vfs,
            defaults,
            contexts: Mutex::new(BTreeMap::new()),
            active: AtomicUsize::new(0),
        })
    }) {
        Ok(registry) => Ok(registry),
        Err(message) => Err(io::Error::other(*message)),
    }
}

/// One bounded namespace lease. The C VFS itself has process lifetime; retiring a lease
/// invalidates future I/O but never frees memory that another SQLite connection could see.
#[derive(Debug)]
pub struct Registered {
    key: u64,
    filename: CString,
    context: Arc<Context>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalContext")
            .field("live", &self.live)
            .finish_non_exhaustive()
    }
}

impl Registered {
    /// Consumes one admitted descriptor and reserves one of 64 active namespace contexts.
    /// Contexts held by foreign file objects continue paying the quota after owner retirement.
    pub fn new(
        storage: Arc<dyn Storage>,
        database: File,
        limits: FileLimits,
        mode: WalMode,
    ) -> io::Result<Self> {
        limits.validate()?;
        if mode == WalMode::Shared
            && (limits.shm_bytes < 32768
                || limits.shm_bytes > 1024 * 1024
                || !limits.shm_bytes.is_multiple_of(32768))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shared WAL index must admit 32 KiB to 1 MiB",
            ));
        }
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let registry = registry()?;
        registry
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_CONTEXTS).then_some(n + 1)
            })
            .map_err(|_| io::Error::other("journal VFS context quota exceeded"))?;
        let reservation = Reservation { registry };
        let key = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("journal VFS keys exhausted"))?;
        let filename = CString::new(format!("/{key}/state.db")).expect("numeric namespace token");
        let context = Arc::new(Context {
            storage,
            limits,
            mode,
            database: Arc::new(database),
            claimed: AtomicBool::new(false),
            sidecars: Mutex::new([None, None]),
            live: AtomicBool::new(true),
            _reservation: reservation,
        });
        context.authority()?;
        registry
            .contexts
            .lock()
            .map_err(|_| io::Error::other("journal VFS registry poisoned"))?
            .insert(key, Arc::downgrade(&context));
        Ok(Self {
            key,
            filename,
            context,
        })
    }

    /// Returns the non-default process-lifetime driver name for SQLite open.
    pub fn name(&self) -> &CStr {
        VFS_NAME
    }
    /// Returns an ephemeral registry token, never a host execution pathname.
    pub fn filename(&self) -> &CStr {
        &self.filename
    }
    /// Borrows the actual main I/O descriptor without creating another file description.
    pub fn database(&self) -> &File {
        &self.context.database
    }

    /// Checks SQLite's actual file object, our method/context markers and retained identity.
    /// This never interprets a builtin private struct or treats a reported name as authority.
    pub fn owns_connection(&self, connection: &Connection) -> io::Result<bool> {
        let mut file: *mut ffi::sqlite3_file = ptr::null_mut();
        // SAFETY: live exclusive Connection borrow, writable pointer output. We only cast
        // sqlite3_file after checking our own methods marker, never a private Unix C struct.
        let code = unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                (&mut file as *mut *mut ffi::sqlite3_file).cast(),
            )
        };
        if code != ffi::SQLITE_OK || file.is_null() || !matches_methods(unsafe { (*file).pMethods })
        {
            return Ok(false);
        }
        let state = unsafe { (*file.cast::<Slot>()).state.as_ref() };
        let Some(state) = state else {
            return Ok(false);
        };
        Ok(state.name == Name::Database
            && Arc::ptr_eq(&state.context, &self.context)
            && Arc::ptr_eq(&state.file, &self.context.database)
            && self.context.storage.contains(Name::Database, &state.file)?)
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.context.live.store(false, Ordering::Release);
        if let Ok(registry) = registry()
            && let Ok(mut contexts) = registry.contexts.lock()
        {
            contexts.remove(&self.key);
        }
    }
}

#[repr(C)]
struct Slot {
    base: ffi::sqlite3_file,
    state: *mut State,
}

struct State {
    context: Arc<Context>,
    file: Arc<File>,
    name: Name,
    lock: c_int,
    shm: Option<shm::SharedMemory>,
}

impl State {
    fn valid(&self) -> io::Result<()> {
        self.context.authority()?;
        if self.name != Name::Database && !self.context.storage.contains(self.name, &self.file)? {
            return Err(io::Error::other("journal sidecar binding changed"));
        }
        Ok(())
    }
}

fn matches_methods(methods: *const ffi::sqlite3_io_methods) -> bool {
    methods == &METHODS || methods == &SHARED_METHODS
}

// Every callback catches Rust panics before crossing SQLite's C ABI. Buffer/pointer validity
// comes from SQLite's documented method contract; null/size/name errors are still rejected.
fn boundary(code: c_int, body: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(code)
}

unsafe fn state<'a>(file: *mut ffi::sqlite3_file) -> &'a mut State {
    unsafe { &mut *(*file.cast::<Slot>()).state }
}

unsafe extern "C" fn open(
    _vfs: *mut ffi::sqlite3_vfs,
    raw: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    output: *mut c_int,
) -> c_int {
    boundary(ffi::SQLITE_CANTOPEN, || {
        unsafe {
            (*file).pMethods = ptr::null();
        }
        let Some((key, name)) = (unsafe { Name::request(raw) }) else {
            return ffi::SQLITE_CANTOPEN;
        };
        let expected = match name {
            Name::Database => ffi::SQLITE_OPEN_MAIN_DB,
            Name::Wal => ffi::SQLITE_OPEN_WAL,
            Name::Rollback => ffi::SQLITE_OPEN_MAIN_JOURNAL,
            Name::Shm => return ffi::SQLITE_CANTOPEN,
        };
        if flags & 0x0fff00 != expected
            || flags & ffi::SQLITE_OPEN_READWRITE == 0
            || flags & (ffi::SQLITE_OPEN_DELETEONCLOSE | ffi::SQLITE_OPEN_URI) != 0
        {
            return ffi::SQLITE_CANTOPEN;
        }
        let Some(ctx) = registry().ok().and_then(|registry| registry.lookup(key)) else {
            return ffi::SQLITE_CANTOPEN;
        };
        if ctx.authority().is_err() {
            return ffi::SQLITE_CANTOPEN;
        }
        let data = if name == Name::Database {
            if flags & ffi::SQLITE_OPEN_EXCLUSIVE != 0 {
                return ffi::SQLITE_CANTOPEN;
            }
            if ctx.claimed.swap(true, Ordering::AcqRel) {
                return ffi::SQLITE_CANTOPEN;
            }
            Arc::clone(&ctx.database)
        } else {
            match ctx.sidecar(
                name,
                flags & ffi::SQLITE_OPEN_CREATE != 0,
                flags & ffi::SQLITE_OPEN_EXCLUSIVE != 0,
            ) {
                Ok(file) => file,
                Err(_) => return ffi::SQLITE_CANTOPEN,
            }
        };
        let data = Box::new(State {
            context: ctx,
            file: data,
            name,
            lock: ffi::SQLITE_LOCK_NONE,
            shm: None,
        });
        let methods = if data.context.mode == WalMode::Shared {
            &SHARED_METHODS
        } else {
            &METHODS
        };
        unsafe {
            (*file.cast::<Slot>()).state = Box::into_raw(data);
            (*file).pMethods = methods;
            if !output.is_null() {
                *output = flags;
            }
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    boundary(ffi::SQLITE_IOERR_CLOSE, || {
        let slot = unsafe { &mut *file.cast::<Slot>() };
        if slot.state.is_null() {
            return ffi::SQLITE_OK;
        }
        // SAFETY: exactly one Box was installed by xOpen; clear before dropping to forbid reuse.
        let data = unsafe { Box::from_raw(slot.state) };
        slot.state = ptr::null_mut();
        slot.base.pMethods = ptr::null();
        if data.name == Name::Database {
            let shm = data
                .shm
                .map_or(Ok(()), |shm| shm.finish(&data.context, false));
            let unlocked =
                record_lock(&data.file, libc::F_UNLCK, 0, 0).map_err(|_| ffi::SQLITE_IOERR_UNLOCK);
            shm.and(unlocked)
                .map_or_else(|code| code, |()| ffi::SQLITE_OK)
        } else {
            ffi::SQLITE_OK
        }
    })
}

fn interval(amount: c_int, offset: i64) -> Option<(usize, u64)> {
    let amount = usize::try_from(amount).ok().filter(|n| *n <= IO_LIMIT)?;
    let offset = u64::try_from(offset).ok()?;
    offset.checked_add(amount as u64)?;
    Some((amount, offset))
}

unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    out: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    boundary(ffi::SQLITE_IOERR_READ, || {
        let Some((amount, offset)) = interval(amount, offset) else {
            return ffi::SQLITE_IOERR_READ;
        };
        if amount == 0 {
            return ffi::SQLITE_OK;
        }
        if out.is_null() {
            return ffi::SQLITE_IOERR_READ;
        }
        let state = unsafe { state(file) };
        if state.valid().is_err() {
            return ffi::SQLITE_IOERR_READ;
        }
        let out = unsafe { std::slice::from_raw_parts_mut(out.cast::<u8>(), amount) };
        let mut used = 0;
        while used < amount {
            match state.file.read_at(&mut out[used..], offset + used as u64) {
                Ok(0) => {
                    out[used..].fill(0);
                    return ffi::SQLITE_IOERR_SHORT_READ;
                }
                Ok(n) => used += n,
                Err(_) => return ffi::SQLITE_IOERR_READ,
            }
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    data: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    boundary(ffi::SQLITE_IOERR_WRITE, || {
        let Some((amount, offset)) = interval(amount, offset) else {
            return ffi::SQLITE_IOERR_WRITE;
        };
        if amount == 0 {
            return ffi::SQLITE_OK;
        }
        if data.is_null() {
            return ffi::SQLITE_IOERR_WRITE;
        }
        let state = unsafe { state(file) };
        if state.valid().is_err() {
            return ffi::SQLITE_IOERR_WRITE;
        }
        if let Err(code) = state.context.growth(state.name, offset + amount as u64) {
            return code;
        }
        let data = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), amount) };
        let mut used = 0;
        while used < amount {
            match state.file.write_at(&data[used..], offset + used as u64) {
                Ok(0) => return ffi::SQLITE_IOERR_WRITE,
                Ok(n) => used += n,
                Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {
                    return ffi::SQLITE_FULL;
                }
                Err(_) => return ffi::SQLITE_IOERR_WRITE,
            }
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, size: i64) -> c_int {
    boundary(ffi::SQLITE_IOERR_TRUNCATE, || {
        let Ok(size) = u64::try_from(size) else {
            return ffi::SQLITE_IOERR_TRUNCATE;
        };
        let state = unsafe { state(file) };
        if state.valid().is_err() {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        if let Err(code) = state.context.growth(state.name, size) {
            return code;
        }
        state
            .file
            .set_len(size)
            .map_or(ffi::SQLITE_IOERR_TRUNCATE, |_| ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    boundary(ffi::SQLITE_IOERR_FSYNC, || {
        let state = unsafe { state(file) };
        if state.valid().is_err() {
            return ffi::SQLITE_IOERR_FSYNC;
        }
        state
            .file
            .sync_all()
            .and_then(|_| state.context.storage.sync())
            .map_or(ffi::SQLITE_IOERR_FSYNC, |_| ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn size(file: *mut ffi::sqlite3_file, out: *mut i64) -> c_int {
    boundary(ffi::SQLITE_IOERR_FSTAT, || {
        let state = unsafe { state(file) };
        if state.valid().is_err() || out.is_null() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        match state
            .file
            .metadata()
            .and_then(|m| i64::try_from(m.len()).map_err(io::Error::other))
        {
            Ok(n) => {
                unsafe {
                    *out = n;
                }
                ffi::SQLITE_OK
            }
            Err(_) => ffi::SQLITE_IOERR_FSTAT,
        }
    })
}

fn record_lock(
    file: &File,
    kind: impl Into<c_int>,
    start: libc::off_t,
    len: libc::off_t,
) -> io::Result<()> {
    // SAFETY: zeroed flock then all fields required by the selected SETLK command, including
    // zero l_pid for Linux OFD locks; live owned descriptor.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = kind.into() as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = start;
    lock.l_len = len;
    // Linux/macOS OFD locks survive closes of unrelated descriptors and conflict with POSIX
    // locks. Builtin-client descriptor-close caveats remain explicit. Other Unix branches
    // are test-only fixtures without production admission.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let command = libc::F_OFD_SETLK;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let command = libc::F_SETLK;
    if unsafe { libc::fcntl(file.as_raw_fd(), command, &lock) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn lock_result(result: io::Result<()>) -> c_int {
    match result {
        Ok(()) => ffi::SQLITE_OK,
        Err(e) if [Some(libc::EAGAIN), Some(libc::EACCES)].contains(&e.raw_os_error()) => {
            ffi::SQLITE_BUSY
        }
        Err(_) => ffi::SQLITE_IOERR_LOCK,
    }
}

unsafe extern "C" fn lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    boundary(ffi::SQLITE_IOERR_LOCK, || {
        let state = unsafe { state(file) };
        if ![
            ffi::SQLITE_LOCK_SHARED,
            ffi::SQLITE_LOCK_RESERVED,
            ffi::SQLITE_LOCK_EXCLUSIVE,
        ]
        .contains(&level)
        {
            return ffi::SQLITE_IOERR_LOCK;
        }
        if state.name != Name::Database || state.valid().is_err() {
            return ffi::SQLITE_IOERR_LOCK;
        }
        if level <= state.lock {
            return ffi::SQLITE_OK;
        }
        let result = (|| {
            if state.lock == ffi::SQLITE_LOCK_NONE {
                record_lock(&state.file, libc::F_RDLCK, PENDING_BYTE, 1)?;
                let shared = record_lock(&state.file, libc::F_RDLCK, SHARED_FIRST, SHARED_SIZE);
                let released = record_lock(&state.file, libc::F_UNLCK, PENDING_BYTE, 1);
                shared?;
                released?;
                state.lock = ffi::SQLITE_LOCK_SHARED;
            }
            if level >= ffi::SQLITE_LOCK_RESERVED && state.lock < ffi::SQLITE_LOCK_RESERVED {
                record_lock(&state.file, libc::F_WRLCK, RESERVED_BYTE, 1)?;
                state.lock = ffi::SQLITE_LOCK_RESERVED;
            }
            if level == ffi::SQLITE_LOCK_EXCLUSIVE {
                record_lock(&state.file, libc::F_WRLCK, PENDING_BYTE, 1)?;
                state.lock = ffi::SQLITE_LOCK_PENDING;
                record_lock(&state.file, libc::F_WRLCK, SHARED_FIRST, SHARED_SIZE)?;
                state.lock = ffi::SQLITE_LOCK_EXCLUSIVE;
            }
            Ok(())
        })();
        lock_result(result)
    })
}

unsafe extern "C" fn unlock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    boundary(ffi::SQLITE_IOERR_UNLOCK, || {
        let state = unsafe { state(file) };
        if state.name != Name::Database {
            return ffi::SQLITE_OK;
        }
        let result = (|| {
            if level == ffi::SQLITE_LOCK_NONE {
                record_lock(&state.file, libc::F_UNLCK, 0, 0)?;
            } else if level == ffi::SQLITE_LOCK_SHARED {
                record_lock(&state.file, libc::F_RDLCK, SHARED_FIRST, SHARED_SIZE)?;
                record_lock(&state.file, libc::F_UNLCK, PENDING_BYTE, 2)?;
            } else {
                return Err(io::Error::other("unsupported lock downgrade"));
            }
            state.lock = level;
            Ok(())
        })();
        result.map_or(ffi::SQLITE_IOERR_UNLOCK, |_| ffi::SQLITE_OK)
    })
}

unsafe extern "C" fn reserved(file: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    boundary(ffi::SQLITE_IOERR_CHECKRESERVEDLOCK, || {
        if out.is_null() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        let state = unsafe { state(file) };
        if state.valid().is_err() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        if state.lock >= ffi::SQLITE_LOCK_RESERVED {
            unsafe {
                *out = 1;
            }
            return ffi::SQLITE_OK;
        }
        let mut query: libc::flock = unsafe { std::mem::zeroed() };
        query.l_type = libc::F_WRLCK as libc::c_short;
        query.l_whence = libc::SEEK_SET as libc::c_short;
        query.l_start = RESERVED_BYTE;
        query.l_len = 1;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let command = libc::F_OFD_GETLK;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let command = libc::F_GETLK;
        if unsafe { libc::fcntl(state.file.as_raw_fd(), command, &mut query) } < 0 {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        unsafe {
            *out = c_int::from(query.l_type != libc::F_UNLCK as libc::c_short);
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn control(file: *mut ffi::sqlite3_file, op: c_int, out: *mut c_void) -> c_int {
    boundary(ffi::SQLITE_IOERR, || {
        if op == ffi::SQLITE_FCNTL_HAS_MOVED && !out.is_null() {
            unsafe {
                *out.cast::<c_int>() = c_int::from(state(file).valid().is_err());
            }
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_NOTFOUND
        }
    })
}

unsafe extern "C" fn sector(_file: *mut ffi::sqlite3_file) -> c_int {
    // Conservative hint matches pinned bundled SQLite's DEFAULT_SECTOR_SIZE. No atomic,
    // safe-append or powersafe-overwrite characteristic is asserted by this VFS.
    4096
}
unsafe extern "C" fn characteristics(_file: *mut ffi::sqlite3_file) -> c_int {
    0
}

static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(size),
    xLock: Some(lock),
    xUnlock: Some(unlock),
    xCheckReservedLock: Some(reserved),
    xFileControl: Some(control),
    xSectorSize: Some(sector),
    xDeviceCharacteristics: Some(characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

static SHARED_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xShmMap: Some(shm::map),
    xShmLock: Some(shm::lock),
    xShmBarrier: Some(shm::barrier),
    xShmUnmap: Some(shm::unmap),
    ..METHODS
};

unsafe extern "C" fn delete(
    _vfs: *mut ffi::sqlite3_vfs,
    raw: *const c_char,
    sync_dir: c_int,
) -> c_int {
    boundary(ffi::SQLITE_IOERR_DELETE, || {
        let Some((key, name)) = (unsafe { Name::request(raw) }) else {
            return ffi::SQLITE_IOERR_DELETE;
        };
        if matches!(name, Name::Database | Name::Shm) {
            return ffi::SQLITE_IOERR_DELETE;
        }
        let Some(ctx) = registry().ok().and_then(|registry| registry.lookup(key)) else {
            return ffi::SQLITE_IOERR_DELETE;
        };
        if ctx.authority().is_err() {
            return ffi::SQLITE_IOERR_DELETE;
        }
        let mut slots = match ctx.sidecars.lock() {
            Ok(s) => s,
            Err(_) => return ffi::SQLITE_IOERR_DELETE,
        };
        let index = if name == Name::Wal { 0 } else { 1 };
        let expected = slots[index].as_deref();
        match ctx.storage.remove(name, expected).and_then(|_| {
            if sync_dir != 0 {
                ctx.storage.sync()
            } else {
                Ok(())
            }
        }) {
            Ok(()) => {
                slots[index] = None;
                ffi::SQLITE_OK
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                slots[index] = None;
                ffi::SQLITE_OK
            }
            Err(_) => ffi::SQLITE_IOERR_DELETE,
        }
    })
}

unsafe extern "C" fn access(
    _vfs: *mut ffi::sqlite3_vfs,
    raw: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    boundary(ffi::SQLITE_IOERR_ACCESS, || {
        if out.is_null()
            || ![
                ffi::SQLITE_ACCESS_EXISTS,
                ffi::SQLITE_ACCESS_READ,
                ffi::SQLITE_ACCESS_READWRITE,
            ]
            .contains(&flags)
        {
            return ffi::SQLITE_IOERR_ACCESS;
        }
        unsafe {
            *out = 0;
        }
        let Some((key, name)) = (unsafe { Name::request(raw) }) else {
            return ffi::SQLITE_IOERR_ACCESS;
        };
        let Some(ctx) = registry().ok().and_then(|registry| registry.lookup(key)) else {
            return ffi::SQLITE_IOERR_ACCESS;
        };
        if ctx.authority().is_err() {
            return ffi::SQLITE_IOERR_ACCESS;
        }
        match ctx.storage.length(name) {
            Ok(Some(bytes)) => {
                unsafe {
                    *out = c_int::from(flags != ffi::SQLITE_ACCESS_EXISTS || bytes != 0);
                }
                ffi::SQLITE_OK
            }
            Ok(None) => ffi::SQLITE_OK,
            Err(_) => ffi::SQLITE_IOERR_ACCESS,
        }
    })
}

unsafe extern "C" fn full_path(
    _vfs: *mut ffi::sqlite3_vfs,
    raw: *const c_char,
    capacity: c_int,
    out: *mut c_char,
) -> c_int {
    boundary(ffi::SQLITE_CANTOPEN, || {
        let Some((key, Name::Database)) = (unsafe { Name::request(raw) }) else {
            return ffi::SQLITE_CANTOPEN;
        };
        let Some(ctx) = registry().ok().and_then(|r| r.lookup(key)) else {
            return ffi::SQLITE_CANTOPEN;
        };
        if ctx.authority().is_err() || out.is_null() {
            return ffi::SQLITE_CANTOPEN;
        }
        // Canonical tokens have no aliases, dot components or host pathname resolution.
        let mut len = 0;
        while unsafe { raw.add(len).read() } != 0 {
            len += 1;
        }
        if usize::try_from(capacity).ok().is_none_or(|n| n <= len) {
            return ffi::SQLITE_CANTOPEN;
        }
        unsafe {
            ptr::copy_nonoverlapping(raw, out, len + 1);
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn dl_open(_: *mut ffi::sqlite3_vfs, _: *const c_char) -> *mut c_void {
    ptr::null_mut()
}
unsafe extern "C" fn dl_error(_: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) {
    if n > 0 && !out.is_null() {
        unsafe {
            *out = 0;
        }
    }
}
unsafe extern "C" fn dl_sym(
    _: *mut ffi::sqlite3_vfs,
    _: *mut c_void,
    _: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    None
}
unsafe extern "C" fn dl_close(_: *mut ffi::sqlite3_vfs, _: *mut c_void) {}
unsafe extern "C" fn last_error(_: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    if n > 0 && !out.is_null() {
        unsafe {
            *out = 0;
        }
    }
    0
}

unsafe extern "C" fn randomness(_vfs: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    boundary(0, || {
        let Ok(registry) = registry() else {
            return ffi::SQLITE_ERROR;
        };
        let default = registry.defaults;
        unsafe { (*default).xRandomness.map_or(0, |f| f(default, n, out)) }
    })
}
unsafe extern "C" fn sleep(_vfs: *mut ffi::sqlite3_vfs, n: c_int) -> c_int {
    boundary(0, || {
        let Ok(registry) = registry() else {
            return ffi::SQLITE_ERROR;
        };
        let default = registry.defaults;
        unsafe { (*default).xSleep.map_or(0, |f| f(default, n)) }
    })
}
unsafe extern "C" fn current_time(_vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    boundary(ffi::SQLITE_ERROR, || {
        let Ok(registry) = registry() else {
            return ffi::SQLITE_ERROR;
        };
        let default = registry.defaults;
        unsafe {
            (*default)
                .xCurrentTime
                .map_or(ffi::SQLITE_ERROR, |f| f(default, out))
        }
    })
}
