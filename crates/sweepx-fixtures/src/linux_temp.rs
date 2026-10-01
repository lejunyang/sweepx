//! Serialized process/clock fixtures for Linux temporary-object report and cleanup tests.
//!
//! This crate is a development dependency of core and CLI. Fixtures never supply production
//! filesystem authority; consumers must opt into the existing observation seams explicitly.

use std::fs;
use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Serializes tests that replace process observation and clock environment variables.
pub struct TestSeams {
    _lock: MutexGuard<'static, ()>,
    /// Owned empty process-observation tree, available for controlled reference fixtures.
    pub proc_root: TempDir,
}

impl Default for TestSeams {
    fn default() -> Self {
        Self::new()
    }
}

impl TestSeams {
    /// Installs empty `/proc` and Unix-socket fixtures without moving the reference clock.
    pub fn new() -> Self {
        let lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let proc_root = TempDir::new().unwrap();
        fs::create_dir_all(proc_root.path().join("self")).unwrap();
        fs::write(proc_root.path().join("self/mountinfo"), b"").unwrap();
        let net_unix = proc_root.path().join("net-unix");
        fs::write(
            &net_unix,
            b"Num       RefCount Protocol Flags    Type St Inode Path\n",
        )
        .unwrap();
        // SAFETY: Tests holding `TEST_ENV_LOCK` are the only users of these process globals.
        unsafe {
            std::env::set_var("SWEEPX_TEST_LINUX_PROC_ROOT", proc_root.path());
            std::env::set_var("SWEEPX_TEST_LINUX_PROC_NET_UNIX", net_unix);
        }
        Self {
            _lock: lock,
            proc_root,
        }
    }

    /// Installs fixtures and projects the reference clock beyond every fixture timestamp.
    pub fn future() -> Self {
        let seams = Self::new();
        // SAFETY: The shared test lock makes this process-global clock deterministic.
        unsafe {
            std::env::set_var("SWEEPX_TEST_LINUX_NOW_UNIX", "4000000000");
        }
        seams
    }
}

impl Drop for TestSeams {
    fn drop(&mut self) {
        // SAFETY: Drop still holds the test-serialization lock.
        unsafe {
            std::env::remove_var("SWEEPX_TEST_LINUX_PROC_ROOT");
            std::env::remove_var("SWEEPX_TEST_LINUX_PROC_NET_UNIX");
            std::env::remove_var("SWEEPX_TEST_LINUX_NOW_UNIX");
        }
    }
}
