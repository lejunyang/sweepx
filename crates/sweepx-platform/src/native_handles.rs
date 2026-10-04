//! Shared admission for scanner and private-storage native I/O owners.
//!
//! Reserve before open/duplicate/create. A lease follows the actual native owner through close,
//! including directory streams and foreign database files. This is a bound on participating
//! primitives, not on unrelated libraries, raw borrowed-handle duplicates or process-wide RSS.

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

const AUTHORITY_LIMIT: usize = 128;
static AUTHORITY_HELD: AtomicUsize = AtomicUsize::new(0);
const IO_LIMIT: usize = 256;
static IO_HELD: AtomicUsize = AtomicUsize::new(0);

/// Typed admission refusal, distinct from missing data, permission failures and lock contention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleLimit {
    /// Stable unit: `native_io_handles` or the storage `native_authority_handles` subset.
    pub resource: &'static str,
    /// Maximum simultaneous owners of this resource; not a whole-process native handle count.
    pub limit: usize,
}

#[derive(Debug)]
struct Exhausted(HandleLimit);
impl std::fmt::Display for Exhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} limit ({})", self.0.resource, self.0.limit)
    }
}
impl std::error::Error for Exhausted {}

/// Identifies a shared admission refusal without interpreting it as unsafe or absent data.
pub fn handle_limit(error: &io::Error) -> Option<HandleLimit> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Exhausted>())
        .map(|inner| inner.0)
}

/// One nonblocking native resource reservation. This establishes no filesystem authority.
/// Store it after the actual native owner so the handle closes before the slot is refunded.
/// Sharing that owner through `Arc` pays once; each real duplicate needs a new I/O lease.
#[derive(Debug)]
pub struct HandleLease(&'static AtomicUsize);
impl HandleLease {
    /// Reserves one of the common 256 scanner/storage native I/O slots before a native open.
    pub fn acquire_io() -> io::Result<Self> {
        Self::acquire_from(&IO_HELD, "native_io_handles", IO_LIMIT)
    }

    /// Reserves one of the 128 storage directory/control-lock owner slots.
    /// Storage owners must additionally acquire an I/O lease; scanners pay only the I/O pool.
    pub fn acquire_storage_authority() -> io::Result<Self> {
        Self::acquire_from(&AUTHORITY_HELD, "native_authority_handles", AUTHORITY_LIMIT)
    }

    fn acquire_from(
        counter: &'static AtomicUsize,
        resource: &'static str,
        limit: usize,
    ) -> io::Result<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < limit).then_some(held + 1)
            })
            .map(|_| Self(counter))
            .map_err(|_| io::Error::other(Exhausted(HandleLimit { resource, limit })))
    }
}
impl Drop for HandleLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "backend-linux"),
    all(target_os = "macos", feature = "backend-macos"),
    all(windows, feature = "backend-windows")
))]
#[derive(Debug)]
pub(crate) struct Admitted<T> {
    handle: T,
    _lease: HandleLease,
}

#[cfg(any(
    all(target_os = "linux", feature = "backend-linux"),
    all(target_os = "macos", feature = "backend-macos"),
    all(windows, feature = "backend-windows")
))]
impl<T> Admitted<T> {
    pub(crate) fn new(handle: T, lease: HandleLease) -> Self {
        Self {
            handle,
            _lease: lease,
        }
    }

    // Unix fdopendir transfers the actual descriptor, not its reservation. On success the
    // stream owner must close with closedir before dropping the separately transferred lease.
    #[cfg(any(
        all(target_os = "linux", feature = "backend-linux"),
        all(target_os = "macos", feature = "backend-macos")
    ))]
    pub(crate) fn into_parts(self) -> (T, HandleLease) {
        (self.handle, self._lease)
    }
}

#[cfg(any(
    all(target_os = "linux", feature = "backend-linux"),
    all(target_os = "macos", feature = "backend-macos"),
    all(windows, feature = "backend-windows")
))]
impl<T> std::ops::Deref for Admitted<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.handle
    }
}
