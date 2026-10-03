//! Thread-local no-materialization policy; metadata prechecks alone cannot close hydration races.

use std::{io, marker::PhantomData, rc::Rc};

// Public Darwin sys/resource.h ABI (not provided by our libc crate).
const MATERIALIZE_DATALESS: i32 = 3;
const THREAD_SCOPE: i32 = 1;
const MATERIALIZE_OFF: i32 = 1;
unsafe extern "C" {
    fn getiopolicy_np(kind: i32, scope: i32) -> i32;
    fn setiopolicy_np(kind: i32, scope: i32, policy: i32) -> i32;
}

/// Disables dataless materialization on the calling OS thread until restoration.
///
/// Enter before opening provider-sensitive paths and retain through all data access.
/// This guard is neither Send nor Sync; restoring another thread would leave the original
/// thread altered. Explicit restore reports failure, while Drop attempts restoration on
/// errors and unwinding. Kernel policy support is not qualification of every cloud provider.
#[must_use = "retain the guard on its issuing thread until protected I/O completes"]
pub struct NoMaterialization {
    previous: i32,
    restored: bool,
    // Restoring on a different OS thread would leave the issuing thread modified.
    _same_thread: PhantomData<Rc<()>>,
}

impl NoMaterialization {
    /// Observes the existing calling-thread policy and sets OFF, refusing unknown policy
    /// values or unsupported/denied calls without permitting an unguarded fallback.
    pub fn enter() -> io::Result<Self> {
        // SAFETY: public ABI operates on the calling thread, with no pointer arguments.
        let previous = unsafe { getiopolicy_np(MATERIALIZE_DATALESS, THREAD_SCOPE) };
        if previous < 0 {
            return Err(io::Error::last_os_error());
        }
        if !(0..=2).contains(&previous) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported calling-thread materialization policy: {previous}"),
            ));
        }
        if unsafe { setiopolicy_np(MATERIALIZE_DATALESS, THREAD_SCOPE, MATERIALIZE_OFF) } != 0 {
            return Err(io::Error::other(format!(
                "cannot prohibit dataless materialization: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Self {
            previous,
            restored: false,
            _same_thread: PhantomData,
        })
    }

    /// Restores the policy observed by enter. On failure, Drop retries, and the caller
    /// must discard read results or refuse publication before its commit point.
    pub fn restore(mut self) -> io::Result<()> {
        // SAFETY: !Send/!Sync guard remains on its issuing thread; previous was queried here.
        if unsafe { setiopolicy_np(MATERIALIZE_DATALESS, THREAD_SCOPE, self.previous) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for NoMaterialization {
    fn drop(&mut self) {
        if !self.restored {
            // SAFETY: same-thread RAII fallback covers errors and unwinding. If restoration
            // fails, the more restrictive OFF policy remains; explicit success uses restore().
            unsafe {
                setiopolicy_np(MATERIALIZE_DATALESS, THREAD_SCOPE, self.previous);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_thread_policy_is_off_inside_guard_and_restored_on_all_exits() {
        // Independent ABI observation, rather than deriving expected policy from guard fields.
        let previous = unsafe { getiopolicy_np(3, 1) };
        let guard = NoMaterialization::enter().expect("thread policy supported");
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
        guard.restore().expect("restore policy");
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        {
            let _guard = NoMaterialization::enter().expect("enter again");
        }
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
    }
    #[test]
    fn nesting_errors_and_unwinding_restore_the_issuing_thread() {
        let previous = unsafe { getiopolicy_np(3, 1) };
        let outer = NoMaterialization::enter().unwrap();
        let inner = NoMaterialization::enter().unwrap();
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
        inner.restore().unwrap();
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
        outer.restore().unwrap();
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        let error: io::Result<()> = (|| {
            let _guard = NoMaterialization::enter()?;
            Err(io::Error::other("controlled operation failure"))
        })();
        assert!(error.is_err());
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        let panic = std::panic::catch_unwind(|| {
            let _guard = NoMaterialization::enter().unwrap();
            panic!("controlled policy unwind");
        });
        assert!(panic.is_err());
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
    }
}
