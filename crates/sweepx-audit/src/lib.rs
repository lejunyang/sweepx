mod clean;

pub use clean::*;

/// Bounded retained-descriptor SQLite storage shared by Unix state components.
#[cfg(any(target_os = "linux", target_os = "macos", all(test, unix)))]
pub mod retained_vfs;
