//! Scan acceleration qualification.
//!
//! The accelerated Windows path reads NTFS metadata in bulk instead of walking directory handles.
//! It is an *optimization only*: the handle-relative traversal stays authoritative, and this module
//! exists to decide whether the fast path may be attempted at all.
//!
//! The decision is deliberately a value rather than an action. Callers can log it, surface it, and
//! assert on it in tests without a volume handle or elevation, which is the only way the fallback
//! behavior can be verified on an ordinary developer machine.

use std::path::Path;
use std::time::Duration;

use sweepx_platform::CancellationToken;

/// Why the accelerated scan path was not used.
///
/// Every variant means "the portable traversal runs instead". The distinctions exist so an
/// operator can tell an expected condition (not elevated) from a real problem (invalid native
/// data), rather than seeing one opaque "acceleration unavailable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelerationRefusal {
    /// The host has no accelerated implementation.
    UnsupportedPlatform,
    /// The root is not a form the accelerator can map to a volume.
    UnsupportedRoot,
    /// The volume is not NTFS.
    UnsupportedFilesystem,
    /// The process lacks the elevation the volume handle requires.
    ///
    /// Measured on Windows: `FSCTL_QUERY_USN_JOURNAL` needs a `GENERIC_READ` volume handle, which
    /// an unelevated token cannot open, and no lower access level exposes the control code at all.
    /// This is therefore the *expected* outcome for a normal user, not a malfunction.
    NotElevated,
    /// A volume handle or control code was refused for a reason other than elevation.
    AccessDeniedOrUnavailable,
    /// Native data failed validation, so it cannot be trusted as a scan source.
    InvalidNativeData,
    /// A bound was hit; partial native data is discarded rather than truncated.
    ResourceLimit,
    /// The scan was cancelled during qualification.
    Cancelled,
}

impl AccelerationRefusal {
    /// A stable machine-readable code.
    ///
    /// Held stable across locales and releases so logs and tests can match on it.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsupportedRoot => "unsupported_root",
            Self::UnsupportedFilesystem => "unsupported_filesystem",
            Self::NotElevated => "not_elevated",
            Self::AccessDeniedOrUnavailable => "access_denied_or_unavailable",
            Self::InvalidNativeData => "invalid_native_data",
            Self::ResourceLimit => "resource_limit",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether elevation alone would plausibly change this outcome.
    ///
    /// Used to decide whether suggesting `--elevate` is honest. Suggesting it for, say,
    /// `UnsupportedFilesystem` would send the user to a UAC prompt that cannot help.
    pub const fn elevation_might_help(self) -> bool {
        matches!(self, Self::NotElevated)
    }
}

/// Whether a scan may use the accelerated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelerationDecision {
    /// The accelerator qualified. `layout_records` is what the probe reported.
    ///
    /// Qualification is not permission to skip verification: the accelerated path must still
    /// produce the same identity evidence as the portable one.
    Qualified { layout_records: u64 },
    /// The portable traversal must be used, for this reason.
    Refused(AccelerationRefusal),
}

impl AccelerationDecision {
    /// Whether the accelerated path may be attempted.
    ///
    /// Only an explicit `Qualified` returns true, so any unmapped future state fails closed to the
    /// traversal that is always correct.
    pub const fn is_qualified(self) -> bool {
        matches!(self, Self::Qualified { .. })
    }

    /// The refusal reason, if any.
    pub const fn refusal(self) -> Option<AccelerationRefusal> {
        match self {
            Self::Qualified { .. } => None,
            Self::Refused(reason) => Some(reason),
        }
    }
}

/// A fast, non-authoritative preview of a scan root read from NTFS metadata.
///
/// Deliberately separate from the scan's real output. A preview entry has a path and a size but
/// **no reopen recipe**, because a recipe is derived from handles the traversal actually held and
/// an MFT snapshot cannot produce one. Nothing may be deleted on the strength of a preview: it
/// exists so a large tree can show totals in about a second instead of after a full walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceleratedPreview {
    /// Number of objects the snapshot found under the root.
    pub entry_count: u64,
    /// Summed logical bytes of those objects.
    ///
    /// A lower bound whenever `complete` is false.
    pub logical_bytes: u128,
    /// Whether every record under the root was accounted for.
    pub complete: bool,
    /// How long the snapshot and selection took.
    pub elapsed: Duration,
}

/// Reads a fast preview of `root`, or explains why it could not.
///
/// Runs only when qualification already succeeded, so the failure modes here are narrow: the
/// volume read itself, or a root whose identity cannot be established. A root whose identity is
/// unknown is refused rather than guessed, since selecting a subtree by name instead of by file
/// reference would let an unrelated tree be reported as the user's.
#[cfg(all(windows, feature = "platform-windows"))]
pub fn read_accelerated_preview(
    root: &Path,
    cancel: &CancellationToken,
) -> Result<AcceleratedPreview, AccelerationRefusal> {
    use sweepx_platform_windows::{
        read_volume_layout_records, root_file_reference, select_subtree,
    };
    // Imported here rather than at module scope: the fallback below does not time anything, so a
    // top-level import is unused on every non-Windows target and fails `-D warnings` there.
    use std::time::Instant;

    let started = Instant::now();
    if cancel.is_cancelled() {
        return Err(AccelerationRefusal::Cancelled);
    }
    let root_reference =
        root_file_reference(root).map_err(|_| AccelerationRefusal::AccessDeniedOrUnavailable)?;
    let records = read_volume_layout_records(root, &|| cancel.is_cancelled()).map_err(|code| {
        match code {
            // ERROR_OPERATION_ABORTED
            995 => AccelerationRefusal::Cancelled,
            // ERROR_MORE_DATA: the bound was hit, so partial data is discarded, not truncated.
            234 => AccelerationRefusal::ResourceLimit,
            13 => AccelerationRefusal::InvalidNativeData,
            _ => AccelerationRefusal::AccessDeniedOrUnavailable,
        }
    })?;
    let subtree = select_subtree(&records, root_reference, root);
    Ok(AcceleratedPreview {
        entry_count: subtree.entries.len() as u64,
        logical_bytes: subtree
            .entries
            .iter()
            .filter(|entry| !entry.is_directory)
            .filter_map(|entry| entry.logical_bytes)
            .map(u128::from)
            .sum(),
        complete: subtree.is_complete(),
        elapsed: started.elapsed(),
    })
}

/// Fallback for hosts without the accelerated reader.
#[cfg(not(all(windows, feature = "platform-windows")))]
pub fn read_accelerated_preview(
    _root: &Path,
    _cancel: &CancellationToken,
) -> Result<AcceleratedPreview, AccelerationRefusal> {
    Err(AccelerationRefusal::UnsupportedPlatform)
}

/// Decides whether `root` qualifies for accelerated scanning.
///
/// Read-only: it inspects privilege and volume metadata and never mutates the filesystem or the
/// USN journal. Cancellation is checked first so a cancelled scan does not open a volume handle.
#[cfg(all(windows, feature = "platform-windows"))]
pub fn qualify_acceleration(root: &Path, cancel: &CancellationToken) -> AccelerationDecision {
    use sweepx_platform_windows::{
        NtfsAccelerationFallback, NtfsAccelerationProbe, probe_ntfs_acceleration,
    };

    match probe_ntfs_acceleration(root, cancel) {
        NtfsAccelerationProbe::Available {
            layout_records,
            journal: _,
        } => AccelerationDecision::Qualified { layout_records },
        NtfsAccelerationProbe::Fallback(reason) => AccelerationDecision::Refused(match reason {
            NtfsAccelerationFallback::UnsupportedPlatform => {
                AccelerationRefusal::UnsupportedPlatform
            }
            NtfsAccelerationFallback::UnsupportedRoot => AccelerationRefusal::UnsupportedRoot,
            NtfsAccelerationFallback::UnsupportedFilesystem => {
                AccelerationRefusal::UnsupportedFilesystem
            }
            NtfsAccelerationFallback::NotElevated => AccelerationRefusal::NotElevated,
            NtfsAccelerationFallback::AccessDeniedOrUnavailable => {
                AccelerationRefusal::AccessDeniedOrUnavailable
            }
            NtfsAccelerationFallback::InvalidNativeData => AccelerationRefusal::InvalidNativeData,
            NtfsAccelerationFallback::ResourceLimit => AccelerationRefusal::ResourceLimit,
            NtfsAccelerationFallback::Cancelled => AccelerationRefusal::Cancelled,
        }),
    }
}

/// Refuses acceleration on hosts without an accelerated implementation.
///
/// Separate from the Windows arm so a missing implementation is a compile-time certainty rather
/// than a runtime hope.
#[cfg(not(all(windows, feature = "platform-windows")))]
pub fn qualify_acceleration(_root: &Path, cancel: &CancellationToken) -> AccelerationDecision {
    if cancel.is_cancelled() {
        return AccelerationDecision::Refused(AccelerationRefusal::Cancelled);
    }
    AccelerationDecision::Refused(AccelerationRefusal::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cancellation must be refused before any volume work is attempted.
    #[test]
    fn a_cancelled_scan_never_qualifies() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let decision = qualify_acceleration(Path::new("."), &cancel);
        assert!(!decision.is_qualified());
        assert_eq!(
            decision.refusal(),
            Some(AccelerationRefusal::Cancelled),
            "a cancelled qualification must say so rather than blaming the platform"
        );
    }

    /// Only `Qualified` may enable the fast path.
    #[test]
    fn every_refusal_falls_back_to_the_portable_traversal() {
        for reason in [
            AccelerationRefusal::UnsupportedPlatform,
            AccelerationRefusal::UnsupportedRoot,
            AccelerationRefusal::UnsupportedFilesystem,
            AccelerationRefusal::NotElevated,
            AccelerationRefusal::AccessDeniedOrUnavailable,
            AccelerationRefusal::InvalidNativeData,
            AccelerationRefusal::ResourceLimit,
            AccelerationRefusal::Cancelled,
        ] {
            let decision = AccelerationDecision::Refused(reason);
            assert!(
                !decision.is_qualified(),
                "{} must not enable acceleration",
                reason.code()
            );
            assert_eq!(decision.refusal(), Some(reason));
            assert!(!reason.code().is_empty());
        }
        assert!(AccelerationDecision::Qualified { layout_records: 1 }.is_qualified());
        assert_eq!(
            AccelerationDecision::Qualified { layout_records: 1 }.refusal(),
            None
        );
    }

    /// Elevation must only be suggested where it could actually help.
    #[test]
    fn elevation_is_only_suggested_when_it_could_help() {
        assert!(AccelerationRefusal::NotElevated.elevation_might_help());
        for reason in [
            AccelerationRefusal::UnsupportedPlatform,
            AccelerationRefusal::UnsupportedRoot,
            AccelerationRefusal::UnsupportedFilesystem,
            AccelerationRefusal::AccessDeniedOrUnavailable,
            AccelerationRefusal::InvalidNativeData,
            AccelerationRefusal::ResourceLimit,
            AccelerationRefusal::Cancelled,
        ] {
            assert!(
                !reason.elevation_might_help(),
                "{} would send the user to a UAC prompt that cannot fix it",
                reason.code()
            );
        }
    }

    /// Machine-readable codes are a stable contract; they must stay unique and snake_case.
    #[test]
    fn refusal_codes_are_unique_and_stable() {
        let codes = [
            AccelerationRefusal::UnsupportedPlatform.code(),
            AccelerationRefusal::UnsupportedRoot.code(),
            AccelerationRefusal::UnsupportedFilesystem.code(),
            AccelerationRefusal::NotElevated.code(),
            AccelerationRefusal::AccessDeniedOrUnavailable.code(),
            AccelerationRefusal::InvalidNativeData.code(),
            AccelerationRefusal::ResourceLimit.code(),
            AccelerationRefusal::Cancelled.code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "refusal codes must be unique");
        assert!(
            codes
                .iter()
                .all(|code| code.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
            "codes are a machine contract and must stay snake_case"
        );
    }

    /// On this unelevated host the real probe must refuse, and say elevation is why.
    ///
    /// This is the branch every ordinary user takes, so it is asserted against the live platform
    /// rather than a fake. It also pins the fail-closed property: no volume handle, no fast path.
    #[cfg(all(windows, feature = "platform-windows"))]
    #[test]
    fn an_unelevated_windows_host_refuses_and_names_elevation() {
        use sweepx_platform::PrivilegeProvider as _;

        let elevated = sweepx_platform_windows::WindowsPrivilegeProvider::new()
            .observe()
            .level
            .grants_elevated_capability();
        let root = std::env::var_os("SystemDrive")
            .map(|drive| std::path::PathBuf::from(format!("{}\\", drive.to_string_lossy())))
            .expect("Windows always defines SystemDrive");
        let decision = qualify_acceleration(&root, &CancellationToken::new());

        if elevated {
            // Elevated runs must not claim the privilege is missing; anything else (for example a
            // non-NTFS volume) is legitimate, so only that one wrong answer is excluded.
            assert_ne!(
                decision.refusal(),
                Some(AccelerationRefusal::NotElevated),
                "an elevated process must not report NotElevated"
            );
        } else {
            assert_eq!(
                decision.refusal(),
                Some(AccelerationRefusal::NotElevated),
                "an unelevated host cannot open the volume handle, so acceleration must be \
                 refused for exactly that reason"
            );
            assert!(!decision.is_qualified());
            assert!(
                decision
                    .refusal()
                    .is_some_and(AccelerationRefusal::elevation_might_help)
            );
        }
    }
}
