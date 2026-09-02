//! Volume change detection built on the NTFS USN change journal.
//!
//! This is the validity half of an incremental scan: it answers "has anything under this volume
//! changed since I last looked?" without walking the tree. A scan result can only be reused when
//! the answer is a confident no, so every ambiguous outcome here resolves to "assume it changed".
//!
//! # Why this is separate from the accelerated reader
//!
//! [`crate::read_volume_layout_records`] answers "what is on the volume right now" and needs
//! elevation. Change detection answers "is what I already have still true", and the bounds query
//! it depends on is far cheaper. Keeping them apart means a caller can validate a cached result
//! without paying for a whole-volume metadata read, which is the entire point of the layer.
//!
//! # What a token does and does not prove
//!
//! A [`VolumeChangeToken`] is evidence about a **volume**, not about a subtree. Two tokens being
//! equal proves no journal activity anywhere on the volume, which is a sufficient condition for a
//! subtree to be unchanged but a much stronger one than necessary. That imprecision is deliberate:
//! narrowing it to a subtree requires resolving every changed record's parent chain, and a wrong
//! answer would serve stale sizes for a directory the user just modified.

use crate::ntfs_acceleration::{UsnCacheMissReason, UsnCursorDecision, UsnJournalBounds};

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
    /// Every record with a smaller USN is already reflected in whatever result the token
    /// accompanies.
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

/// Whether a previously captured token still describes the volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeVerdict {
    /// The journal has not advanced: nothing on the volume changed.
    Unchanged,
    /// The journal advanced. The range that must be examined is `from..to`.
    ///
    /// Carrying the range rather than a bare "changed" lets a caller read exactly the records it
    /// has not seen instead of rescanning the volume.
    Changed { from: i64, to: i64 },
    /// Reuse is impossible and a full rescan is required.
    ///
    /// Distinct from `Changed` because there is no usable range to read: the history that would
    /// explain the difference is gone or was never comparable.
    MustRescan(UsnCacheMissReason),
}

impl ChangeVerdict {
    /// Whether a cached result may be reused without any further work.
    ///
    /// Only `Unchanged` qualifies. `Changed` still carries reusable history, but acting on it
    /// requires applying that history, which is not the same as reuse.
    #[must_use]
    pub const fn permits_reuse(self) -> bool {
        matches!(self, Self::Unchanged)
    }

    /// Stable machine-readable code, for reporting why a scan could not reuse its cache.
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
/// Delegates the trust decision to [`crate::validate_usn_cursor`] rather than repeating its
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
    match crate::validate_usn_cursor(token.journal_id, token.next_usn, current) {
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

    /// A quiet volume must compare equal, which is the only case that permits reuse.
    #[test]
    fn an_unchanged_volume_permits_reuse() {
        let current = bounds(7, 100, 500);
        let token = VolumeChangeToken::capture(current);
        let verdict = compare_to_current(token, current);
        assert_eq!(verdict, ChangeVerdict::Unchanged);
        assert!(verdict.permits_reuse());
    }

    /// Activity must be reported as a bounded range, not as a bare flag.
    #[test]
    fn an_advanced_journal_reports_the_range_to_examine() {
        let token = VolumeChangeToken::capture(bounds(7, 100, 500));
        let verdict = compare_to_current(token, bounds(7, 100, 900));
        assert_eq!(verdict, ChangeVerdict::Changed { from: 500, to: 900 });
        assert!(
            !verdict.permits_reuse(),
            "a changed volume must not be reused before its history is applied"
        );
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
        assert!(!verdict.permits_reuse());
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

    /// Only `Unchanged` may ever permit reuse; every other verdict must withhold it.
    ///
    /// Asserted exhaustively because this predicate is the single gate protecting a user from
    /// being shown sizes for a tree that has since changed.
    #[test]
    fn no_verdict_other_than_unchanged_permits_reuse() {
        let verdicts = [
            ChangeVerdict::Changed { from: 1, to: 2 },
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalChanged),
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalWrapped),
            ChangeVerdict::MustRescan(UsnCacheMissReason::CursorAhead),
            ChangeVerdict::MustRescan(UsnCacheMissReason::InvalidBounds),
        ];
        for verdict in verdicts {
            assert!(
                !verdict.permits_reuse(),
                "{} must not permit reuse",
                verdict.code()
            );
        }
        assert!(ChangeVerdict::Unchanged.permits_reuse());
    }

    /// Codes are a reporting contract and must stay unique and snake_case.
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
