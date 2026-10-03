//! Volume change detection built on the NTFS USN change journal.
//!
//! A cursor comparison describes delivered journal records, not current filesystem facts.
//! Journal replacement, wrap or malformed bounds refuse history use. Matching positions only
//! say the journal has not advanced; they are not permission to skip native observations.
//!
//! NTFS coalesces repeated changes of the same reason while a file remains open. A later write
//! can therefore change file contents or allocation without advancing these bounds until close.
//! Capturing before a walk and covering every volume still does not eliminate this case.
//! See Microsoft's [change journal contract](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-records).
//!
//! Bounds queries are independent of the expensive volume-layout preview. They retain useful
//! history diagnostics without supplying a second filesystem-fact validity implementation.

use crate::windows::ntfs_acceleration::{UsnCacheMissReason, UsnCursorDecision, UsnJournalBounds};

/// A captured point in a volume's USN change journal.
///
/// Comparable only against another token from the same volume. The journal id is part of the
/// identity because a journal that was deleted and recreated restarts its numbering, so a USN
/// alone would compare two unrelated sequences as if they were one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeChangeToken {
    /// Identifies this incarnation of the journal.
    pub journal_id: u64,
    /// The USN the volume had reached when this token was captured.
    ///
    /// This records the journal position only. Capture ordering and the scope/identity of
    /// any accompanying observations must be established separately.
    pub next_usn: i64,
}

impl VolumeChangeToken {
    /// Captures the current position of `bounds`.
    #[must_use]
    pub const fn capture(bounds: UsnJournalBounds) -> Self {
        Self {
            journal_id: bounds.journal_id,
            next_usn: bounds.next_usn,
        }
    }
}

/// Comparison of a captured token with the current journal bounds, not file-fact validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeVerdict {
    /// The journal has not advanced; filesystem facts may still have changed.
    Unchanged,
    /// The journal advanced. The range that must be examined is `from..to`.
    ///
    /// Carrying the range lets a caller request records it has not seen. Those records are
    /// advisory invalidation input; the range alone cannot justify skipping native observations.
    Changed { from: i64, to: i64 },
    /// Reuse is impossible and a full rescan is required.
    ///
    /// Distinct from `Changed` because there is no usable range to read: the history that would
    /// explain the difference is gone or was never comparable.
    MustRescan(UsnCacheMissReason),
}

impl ChangeVerdict {
    /// Stable machine-readable code for journal comparison diagnostics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Changed { .. } => "changed",
            Self::MustRescan(UsnCacheMissReason::JournalChanged) => "journal_changed",
            Self::MustRescan(UsnCacheMissReason::JournalWrapped) => "journal_wrapped",
            Self::MustRescan(UsnCacheMissReason::CursorAhead) => "cursor_ahead",
            Self::MustRescan(UsnCacheMissReason::InvalidBounds) => "invalid_bounds",
        }
    }
}

/// Compares a captured token against the volume's current journal bounds.
///
/// Delegates the cursor-range check to [`crate::windows::validate_usn_cursor`] rather than repeating its
/// comparisons: that function already refuses a changed journal id, a wrapped range and an
/// impossible cursor, and a second implementation of the same rules could disagree with it. The
/// only judgement added here is turning an accepted cursor into either `Unchanged` or an explicit
/// range to examine.
///
/// A token from the future (`CursorAhead`) is treated as a rescan rather than an error. It happens
/// legitimately when a volume is restored from an image or a token outlives its volume, and in
/// both cases the safe interpretation is that the cached result describes something else.
#[must_use]
pub fn compare_to_current(token: VolumeChangeToken, current: UsnJournalBounds) -> ChangeVerdict {
    match crate::windows::validate_usn_cursor(token.journal_id, token.next_usn, current) {
        UsnCursorDecision::CacheMiss(reason) => ChangeVerdict::MustRescan(reason),
        UsnCursorDecision::ReadFrom(cursor) if cursor == current.next_usn => {
            ChangeVerdict::Unchanged
        }
        UsnCursorDecision::ReadFrom(cursor) => ChangeVerdict::Changed {
            from: cursor,
            to: current.next_usn,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(journal_id: u64, first: i64, next: i64) -> UsnJournalBounds {
        UsnJournalBounds {
            journal_id,
            first_usn: first,
            next_usn: next,
            lowest_valid_usn: first,
        }
    }

    /// Equal journal positions retain their stable diagnostic without granting fact authority.
    #[test]
    fn equal_positions_report_only_an_unchanged_journal() {
        let current = bounds(7, 100, 500);
        let token = VolumeChangeToken::capture(current);
        let verdict = compare_to_current(token, current);
        assert_eq!(verdict, ChangeVerdict::Unchanged);
    }

    /// Activity must be reported as a bounded range, not as a bare flag.
    #[test]
    fn an_advanced_journal_reports_the_range_to_examine() {
        let token = VolumeChangeToken::capture(bounds(7, 100, 500));
        let verdict = compare_to_current(token, bounds(7, 100, 900));
        assert_eq!(verdict, ChangeVerdict::Changed { from: 500, to: 900 });
    }

    /// A recreated journal restarts numbering, so the USN alone would be misleading.
    ///
    /// Without the journal id this case can look like `Unchanged`: the token's USN can coincide
    /// with a position in the new sequence that has nothing to do with it.
    #[test]
    fn a_recreated_journal_is_never_reusable_even_at_the_same_usn() {
        let token = VolumeChangeToken::capture(bounds(7, 100, 500));
        let verdict = compare_to_current(token, bounds(8, 100, 500));
        assert_eq!(
            verdict,
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalChanged)
        );
    }

    /// History older than the token was discarded, so the difference cannot be reconstructed.
    #[test]
    fn a_wrapped_journal_forces_a_rescan() {
        let token = VolumeChangeToken::capture(bounds(7, 100, 500));
        let verdict = compare_to_current(token, bounds(7, 600, 900));
        assert_eq!(
            verdict,
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalWrapped)
        );
    }

    /// A token ahead of the volume describes a different volume state, not a newer one.
    #[test]
    fn a_token_from_the_future_forces_a_rescan() {
        let token = VolumeChangeToken::capture(bounds(7, 100, 900));
        let verdict = compare_to_current(token, bounds(7, 100, 500));
        assert_eq!(
            verdict,
            ChangeVerdict::MustRescan(UsnCacheMissReason::CursorAhead)
        );
    }

    /// Incoherent bounds must fail closed rather than being interpreted.
    #[test]
    fn incoherent_bounds_fail_closed() {
        let token = VolumeChangeToken::capture(bounds(7, 100, 500));
        let verdict = compare_to_current(
            token,
            UsnJournalBounds {
                journal_id: 7,
                first_usn: 900,
                next_usn: 100,
                lowest_valid_usn: 900,
            },
        );
        assert_eq!(
            verdict,
            ChangeVerdict::MustRescan(UsnCacheMissReason::InvalidBounds)
        );
    }

    #[test]
    fn verdict_codes_are_unique_and_stable() {
        let codes = [
            ChangeVerdict::Unchanged.code(),
            ChangeVerdict::Changed { from: 1, to: 2 }.code(),
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalChanged).code(),
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalWrapped).code(),
            ChangeVerdict::MustRescan(UsnCacheMissReason::CursorAhead).code(),
            ChangeVerdict::MustRescan(UsnCacheMissReason::InvalidBounds).code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "verdict codes must be unique");
        assert!(
            codes
                .iter()
                .all(|code| code.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
            "codes are a machine contract and must stay snake_case"
        );
    }
}
