//! Thread-local no-materialization policy; metadata prechecks alone cannot close hydration races.

use std::{io, marker::PhantomData, rc::Rc};

use crate::BoundedRegularFileReadError;

// Public Darwin sys/resource.h ABI (not provided by our libc crate).
const MATERIALIZE_DATALESS: i32 = 3;
const THREAD_SCOPE: i32 = 1;
const MATERIALIZE_OFF: i32 = 1;
unsafe extern "C" {
    fn getiopolicy_np(kind: i32, scope: i32) -> i32;
    fn setiopolicy_np(kind: i32, scope: i32, policy: i32) -> i32;
}

pub(super) struct NoMaterialization {
    previous: i32,
    restored: bool,
    // Restoring on a different OS thread would leave the issuing thread modified.
    _same_thread: PhantomData<Rc<()>>,
}

impl NoMaterialization {
    pub(super) fn enter() -> Result<Self, BoundedRegularFileReadError> {
        // SAFETY: public ABI operates on the calling thread, with no pointer arguments.
        let previous = unsafe { getiopolicy_np(MATERIALIZE_DATALESS, THREAD_SCOPE) };
        if !(0..=2).contains(&previous) {
            return Err(BoundedRegularFileReadError::ProviderOrOffline(format!(
                "cannot observe no-materialization policy: {}",
                io::Error::last_os_error()
            )));
        }
        if unsafe { setiopolicy_np(MATERIALIZE_DATALESS, THREAD_SCOPE, MATERIALIZE_OFF) } != 0 {
            return Err(BoundedRegularFileReadError::ProviderOrOffline(format!(
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

    pub(super) fn restore(mut self) -> Result<(), BoundedRegularFileReadError> {
        // SAFETY: !Send/!Sync guard remains on its issuing thread; previous was queried here.
        if unsafe { setiopolicy_np(MATERIALIZE_DATALESS, THREAD_SCOPE, self.previous) } != 0 {
            return Err(BoundedRegularFileReadError::io(io::Error::last_os_error()));
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
}
