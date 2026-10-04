//! Shared admission for retained native directory and control-lock owners.
//!
//! Each successful acquisition precedes an open/duplicate/create. The owner stores its native
//! handle before its lease, so closing happens before another acquisition can reuse the slot.
//! Arc clones of an owner do not open another handle or pay twice. This covers these primitives,
//! not arbitrary exported File duplicates, SQLite data files, scanners or total process handles.

use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};

const LIMIT: usize = 128;
static HELD: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct Exhausted;
impl std::fmt::Display for Exhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "native_authority_handles limit ({LIMIT})")
    }
}
impl std::error::Error for Exhausted {}

pub(super) fn limit(error: &io::Error) -> Option<usize> {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<Exhausted>())
        .then_some(LIMIT)
}

#[derive(Debug)]
pub(super) struct Lease;
impl Lease {
    pub(super) fn acquire() -> io::Result<Self> {
        HELD.fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
            (held < LIMIT).then_some(held + 1)
        })
        .map(|_| Self)
        .map_err(|_| io::Error::other(Exhausted))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        HELD.fetch_sub(1, Ordering::AcqRel);
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
