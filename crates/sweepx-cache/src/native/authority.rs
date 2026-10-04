//! Shared admission for native storage handles and retained authority owners.
//!
//! Each successful acquisition precedes an open/duplicate/create. The owner stores its native
//! handle before its lease, so closing happens before another acquisition can reuse the slot.
//! Arc clones of an owner do not open another handle or pay twice. This covers these primitives,
//! not arbitrary duplicates made through borrowed raw handles or total process handles. Scanner opens
//! share the I/O allowance through the same platform-owned primitive.

use std::ops::Deref;
pub(super) use sweepx_platform::native_handles::HandleLease as Lease;

#[derive(Debug)]
pub(super) struct Owner<T> {
    handle: T,
    _lease: Lease,
}
impl<T> Owner<T> {
    pub(super) fn new(handle: T, lease: Lease) -> Self {
        Self {
            handle,
            _lease: lease,
        }
    }
}
impl<T> Deref for Owner<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.handle
    }
}
