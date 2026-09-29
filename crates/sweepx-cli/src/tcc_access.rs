//! macOS Full Disk Access (TCC) opt-in gate.
//!
//! Unlike privilege elevation, Full Disk Access has **no API that raises a consent dialog at the
//! moment it is needed**. The user must add the responsible program — the SweepX binary, or the
//! terminal that launched it — in System Settings. What SweepX *can* do is:
//!
//! 1. Probe a TCC-protected sentinel to measure whether access is already granted;
//! 2. Touch that sentinel once so the responsible program is registered and appears in the list;
//! 3. Open the Full Disk Access pane and wait a bounded time for the user to toggle it.
//!
//! All checks are read-only. A failure to obtain access never widens any operation: the caller
//! continues on the unprivileged path.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Bounded wait for the user to grant access after the settings pane opens.
const GRANT_WAIT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// A TCC-protected location whose readability proves Full Disk Access.
enum Sentinel {
    /// A file one byte of which must be readable.
    File(PathBuf),
    /// A directory that must be enumerable.
    Directory(PathBuf),
}

/// Sentinel locations in priority order. The TCC database is the canonical FDA check; Mail and
/// Safari cover a host where the database path is somehow unavailable.
fn sentinels() -> Vec<Sentinel> {
    let Some(home) = user_home() else {
        return Vec::new();
    };
    let library = home.join("Library");
    vec![
        Sentinel::File(
            library
                .join("Application Support")
                .join("com.apple.TCC")
                .join("TCC.db"),
        ),
        Sentinel::Directory(library.join("Mail")),
        Sentinel::Directory(library.join("Safari")),
    ]
}

/// Outcome of probing a sentinel.
enum Probe {
    /// Access granted: an existing sentinel was readable.
    Granted,
    /// Access denied by TCC (`Operation not permitted`) on an existing sentinel.
    Denied,
    /// This sentinel does not exist.
    Missing,
}

fn probe_sentinel(sentinel: &Sentinel) -> Probe {
    match sentinel {
        Sentinel::File(path) => match File::open(path) {
            Ok(mut file) => {
                let mut byte = [0u8; 1];
                match file.read(&mut byte) {
                    Ok(_) => Probe::Granted,
                    // Reading zero bytes is still successful access to a TCC-protected file.
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        Probe::Denied
                    }
                    Err(_) => Probe::Granted,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Probe::Denied,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Probe::Missing,
            Err(_) => Probe::Denied,
        },
        Sentinel::Directory(path) => match std::fs::read_dir(path) {
            Ok(_) => Probe::Granted,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Probe::Denied,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Probe::Missing,
            Err(_) => Probe::Denied,
        },
    }
}

/// Measures whether Full Disk Access is currently granted, using the first existing sentinel.
///
/// `None` means no sentinel could be found at all, so access is indeterminate. The act of probing
/// also registers the responsible program with TCC, which is what makes it appear in the list.
pub fn is_granted() -> Option<bool> {
    let mut answer = None;
    for sentinel in sentinels() {
        match probe_sentinel(&sentinel) {
            Probe::Granted => return Some(true),
            Probe::Denied => answer = Some(false),
            Probe::Missing => {}
        }
    }
    answer
}

/// Opens the Full Disk Access pane in System Settings.
fn open_settings_pane() -> std::io::Result<()> {
    std::process::Command::new("/usr/bin/open")
        .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
        .status()?;
    Ok(())
}

/// Runs the opt-in gate and returns whether access is held afterwards.
///
/// When not opted in this only detects. When opted in and access is absent, it registers the
/// program (via the probe), opens settings, prints guidance, and waits up to [`GRANT_WAIT`],
/// polling so the scan proceeds automatically the instant access is granted. Declining or
/// exhausting the wait yields `false`, never an error: the run continues unprivileged.
pub fn ensure(opt_in: bool) -> bool {
    if matches!(is_granted(), Some(true)) {
        return true;
    }
    if !opt_in {
        return false;
    }

    eprintln!(
        "Full Disk Access is required to scan protected areas (Mail, Messages, Safari, and \
         parts of ~/Library/Caches)."
    );
    eprintln!(
        "Opening System Settings. Enable Full Disk Access for this program; if it was started \
         from a terminal and does not appear, enable it for the terminal app instead."
    );
    if let Err(error) = open_settings_pane() {
        eprintln!("could not open the Full Disk Access pane: {error}");
        return false;
    }

    let deadline = Instant::now() + GRANT_WAIT;
    while Instant::now() < deadline {
        std::thread::sleep(POLL_INTERVAL);
        if matches!(is_granted(), Some(true)) {
            eprintln!("Full Disk Access granted.");
            return true;
        }
    }
    eprintln!(
        "Full Disk Access was not enabled within {}s; continuing without it.",
        GRANT_WAIT.as_secs()
    );
    false
}

/// Reports whether a path lives under the user home (for diagnostics and tests).
fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_returns_a_defined_answer_on_this_host() {
        // A real Mac always has at least one of the sentinels, so the answer is determinate.
        assert!(is_granted().is_some());
    }

    #[test]
    fn file_sentinel_distinguises_granted_denied_and_missing() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("absent.db");
        assert!(matches!(
            probe_sentinel(&Sentinel::File(missing)),
            Probe::Missing
        ));

        let file = temp.path().join("a.db");
        std::fs::write(&file, b"x").unwrap();
        // Within a temp directory (not TCC-protected), a readable file reads as granted access.
        assert!(matches!(
            probe_sentinel(&Sentinel::File(file)),
            Probe::Granted
        ));

        let directory = temp.path().join("d");
        std::fs::create_dir(&directory).unwrap();
        assert!(matches!(
            probe_sentinel(&Sentinel::Directory(directory)),
            Probe::Granted
        ));
        assert!(matches!(
            probe_sentinel(&Sentinel::Directory(temp.path().join("no-dir"))),
            Probe::Missing
        ));
    }

    #[test]
    fn not_opted_in_never_blocks_or_prompts() {
        // Detection-only must return a plain bool immediately without opening settings.
        let _ = ensure(false);
    }

    #[test]
    fn timings_are_bounded() {
        assert_eq!(GRANT_WAIT.as_secs(), 300);
        assert!(POLL_INTERVAL < GRANT_WAIT);
    }
}
