//! Shared admission for native storage handles and retained authority owners.
//!
//! Each successful acquisition precedes an open/duplicate/create. The owner stores its native
//! handle before its lease, so closing happens before another acquisition can reuse the slot.
//! Arc clones of an owner do not open another handle or pay twice. This covers these primitives,
//! not arbitrary duplicates made through borrowed raw handles, scanners or total process handles.

use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};

const LIMIT: usize = 128;
static HELD: AtomicUsize = AtomicUsize::new(0);
const IO_LIMIT: usize = 256;
static IO_HELD: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct Exhausted(super::HandleLimit);
impl std::fmt::Display for Exhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} limit ({})", self.0.resource, self.0.limit)
    }
}
impl std::error::Error for Exhausted {}

pub(super) fn limit(error: &io::Error) -> Option<super::HandleLimit> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Exhausted>())
        .map(|inner| inner.0)
}

#[derive(Debug)]
pub(super) struct Lease(&'static AtomicUsize);
impl Lease {
    pub(super) fn acquire() -> io::Result<Self> {
        Self::acquire_from(&HELD, "native_authority_handles", LIMIT)
    }
    pub(super) fn acquire_io() -> io::Result<Self> {
        Self::acquire_from(&IO_HELD, "native_io_handles", IO_LIMIT)
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
            .map_err(|_| io::Error::other(Exhausted(super::HandleLimit { resource, limit })))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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
