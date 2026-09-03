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
//!
//! # Why bare token comparison is not enough
//!
//! A cache that lives on the volume it describes invalidates itself. Writing the cache is
//! journalled on that volume, so the position recorded alongside a scan is stale the moment it
//! lands: measured on this host, a cache-shaped write advances the volume USN by roughly 1080.
//! Because the default state directory is under `%LOCALAPPDATA%`, this is the *common* case, not a
//! corner one, and it made the whole layer useless for scans of the system volume.
//!
//! Capturing the token after the write instead does not converge — that write is journalled too,
//! measured across four consecutive runs that all reported `changed`. So the range is read instead:
//! [`attribute_changes`] decides whether *every* record in it belongs to the cache's own
//! directories, and only then is the volume treated as quiet.

use std::path::{Path, PathBuf};

use crate::ntfs_acceleration::{
    UsnCacheMissReason, UsnCursorDecision, UsnJournalBounds, UsnV2Record,
};

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

/// Whether the changes in a journal range are all attributable to a known writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeAttribution {
    /// Every record in the range was produced by the excluded directory.
    ///
    /// A cached result may be reused: the only thing that touched the volume was the cache itself.
    OnlyExcluded {
        /// How many records were examined and dismissed. Zero means the range was empty.
        attributed: usize,
    },
    /// At least one record came from somewhere else, so the volume really did change.
    ///
    /// Carries one example to make a report actionable rather than merely negative.
    Foreign {
        /// Total records examined, including attributed ones.
        examined: usize,
        /// The reference number of the first record that could not be attributed.
        first_foreign_reference: u64,
    },
    /// The range could not be examined and must be treated as changed.
    ///
    /// Separate from `Foreign` because nothing is known about the contents: a caller may want to
    /// report "could not verify" differently from "something else wrote", even though both refuse
    /// reuse.
    Undetermined {
        /// Stable reason code.
        reason: &'static str,
    },
}

impl ChangeAttribution {
    /// Whether reuse is permitted. Only a fully attributed range qualifies.
    #[must_use]
    pub const fn permits_reuse(&self) -> bool {
        matches!(self, Self::OnlyExcluded { .. })
    }

    /// Stable machine-readable code for reporting.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OnlyExcluded { .. } => "only_excluded",
            Self::Foreign { .. } => "foreign_change",
            Self::Undetermined { reason } => reason,
        }
    }
}

/// Identifies the directories whose own writes should not count as volume changes.
///
/// Membership is decided by **parent reference number**, never by name. A name comparison would let
/// any process invalidate — or worse, spoof — the exclusion by creating a file called
/// `current.json` somewhere else on the volume. Reference numbers are read from open handles to the
/// real directories, so each names exactly one object.
///
/// Several directories are supported because a cache write is not confined to one: the generation
/// payload lands in `generations/` while the pointer lands in the parent, so both move the journal
/// on every write and both must be excluded or nothing verifies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExcludedWriter {
    /// Reference numbers of the directories whose direct children are ignored.
    ///
    /// Empty means nothing is excluded, which makes attribution refuse any non-empty range. That is
    /// the correct failure direction: an exclusion set that could not be resolved must not silently
    /// widen into "dismiss everything".
    pub directory_references: Vec<u64>,
}

impl ExcludedWriter {
    /// Excludes a single directory.
    #[must_use]
    pub fn just(directory_reference: u64) -> Self {
        Self {
            directory_references: vec![directory_reference],
        }
    }

    /// Whether `reference` names one of the excluded directories.
    #[must_use]
    fn contains(&self, reference: u64) -> bool {
        self.directory_references.contains(&reference)
    }
}

/// Decides whether a changed range is entirely explained by `excluded`.
///
/// This is what makes a same-volume cache verifiable. The cache writes only into its own
/// directories, so a range containing nothing but records parented to those proves the rest of the
/// volume was quiet.
///
/// # Why this fails closed on anything unexpected
///
/// The exclusion is narrow on purpose:
///
/// - Only **direct children** of an excluded directory are attributed. A record parented deeper is
///   foreign, because the cache creates no nested directories and a nested write is therefore not
///   ours to dismiss.
/// - A record **for an excluded directory itself** is attributed, since writing a child updates the
///   parent's own timestamps and link count.
/// - Anything else — including a record whose parent is unknown — is foreign.
///
/// The asymmetry is deliberate: wrongly calling a range foreign costs one unnecessary rescan, while
/// wrongly attributing one serves stale sizes for a tree the user just changed.
#[must_use]
pub fn attribute_changes(records: &[UsnV2Record], excluded: &ExcludedWriter) -> ChangeAttribution {
    let mut attributed = 0usize;
    for record in records {
        let is_ours = excluded.contains(record.parent_file_reference_number)
            || excluded.contains(record.file_reference_number);
        if is_ours {
            attributed += 1;
            continue;
        }
        return ChangeAttribution::Foreign {
            examined: records.len(),
            first_foreign_reference: record.file_reference_number,
        };
    }
    ChangeAttribution::OnlyExcluded { attributed }
}

/// Refines a `Changed` verdict by reading the records that explain it.
///
/// `read_range` is the fallible journal read, injected so the decision logic can be exercised
/// without a volume handle. It receives the half-open USN range and returns the records in it.
///
/// A verdict other than `Changed` passes through untouched: `Unchanged` needs no explanation and
/// `MustRescan` has no readable history by definition.
pub fn refine_verdict<E>(
    verdict: ChangeVerdict,
    excluded: &ExcludedWriter,
    read_range: impl FnOnce(i64, i64) -> Result<Vec<UsnV2Record>, E>,
) -> RefinedVerdict {
    let ChangeVerdict::Changed { from, to } = verdict else {
        return RefinedVerdict {
            verdict,
            attribution: None,
        };
    };
    match read_range(from, to) {
        Ok(records) => {
            let attribution = attribute_changes(&records, excluded);
            RefinedVerdict {
                // Only a fully attributed range is promoted back to `Unchanged`; the original
                // verdict is preserved otherwise so no information is lost.
                verdict: if attribution.permits_reuse() {
                    ChangeVerdict::Unchanged
                } else {
                    verdict
                },
                attribution: Some(attribution),
            }
        }
        Err(_) => RefinedVerdict {
            verdict,
            attribution: Some(ChangeAttribution::Undetermined {
                reason: "journal_range_unreadable",
            }),
        },
    }
}

/// A verdict plus, when one was needed, the attribution that refined it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedVerdict {
    /// The verdict after attribution. `Unchanged` here permits reuse.
    pub verdict: ChangeVerdict,
    /// `None` when no journal read was necessary.
    pub attribution: Option<ChangeAttribution>,
}

impl RefinedVerdict {
    /// Whether a cached result may be reused.
    #[must_use]
    pub const fn permits_reuse(&self) -> bool {
        self.verdict.permits_reuse()
    }

    /// The most specific code available, preferring the attribution when there is one.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match &self.attribution {
            Some(attribution) => attribution.code(),
            None => self.verdict.code(),
        }
    }
}

/// The volume root that owns `path`, as the journal is per volume.
///
/// Returns `None` for a path with no drive prefix, such as a UNC share, where there is no volume
/// whose journal could be read.
#[must_use]
pub fn volume_root_of(path: &Path) -> Option<PathBuf> {
    match path.components().next() {
        Some(std::path::Component::Prefix(prefix)) => {
            let text = prefix.as_os_str().to_string_lossy().to_string();
            // A drive prefix is `C:`; anything else (UNC, device namespace) has no drive letter
            // whose journal this crate knows how to open.
            if text.len() == 2 && text.ends_with(':') {
                Some(PathBuf::from(format!("{text}\\")))
            } else {
                None
            }
        }
        _ => None,
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
            ChangeAttribution::OnlyExcluded { attributed: 1 }.code(),
            ChangeAttribution::Foreign {
                examined: 1,
                first_foreign_reference: 2,
            }
            .code(),
            ChangeAttribution::Undetermined {
                reason: "journal_range_unreadable",
            }
            .code(),
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

    /// Builds a change record with an explicit parent, which is what attribution keys on.
    fn record(reference: u64, parent: u64) -> UsnV2Record {
        UsnV2Record {
            file_reference_number: reference,
            parent_file_reference_number: parent,
            usn: 100,
            reason: 0x8000_0000, // USN_REASON_CLOSE
            file_attributes: 0x80,
            name: "x".encode_utf16().collect(),
        }
    }

    /// Reference number standing in for the cache directory in these tests.
    const CACHE_REF: u64 = 4242;

    fn cache_dir() -> ExcludedWriter {
        ExcludedWriter::just(CACHE_REF)
    }

    /// The whole point of the layer: a range containing only cache writes still permits reuse.
    #[test]
    fn a_range_containing_only_cache_writes_permits_reuse() {
        let records = [
            record(11, CACHE_REF),
            record(12, CACHE_REF),
            // The directory's own record: writing a child updates the parent's metadata.
            record(CACHE_REF, 9),
        ];
        let attribution = attribute_changes(&records, &cache_dir());
        assert_eq!(
            attribution,
            ChangeAttribution::OnlyExcluded { attributed: 3 },
            "cache-only activity must not invalidate the cache that produced it"
        );
        assert!(attribution.permits_reuse());
    }

    /// One unrelated write anywhere in the range must refuse reuse.
    ///
    /// Ordered last on purpose: an implementation that stopped at the first attributed record, or
    /// that counted attributions and compared against the total, could pass a check that put the
    /// foreign record first.
    #[test]
    fn a_single_foreign_record_at_the_end_refuses_reuse() {
        let records = [
            record(11, CACHE_REF),
            record(12, CACHE_REF),
            record(77, 5000),
        ];
        let attribution = attribute_changes(&records, &cache_dir());
        assert_eq!(
            attribution,
            ChangeAttribution::Foreign {
                examined: 3,
                first_foreign_reference: 77,
            }
        );
        assert!(!attribution.permits_reuse());
    }

    /// An empty range is trivially attributable, since nothing happened.
    #[test]
    fn an_empty_range_is_attributable() {
        let attribution = attribute_changes(&[], &cache_dir());
        assert_eq!(
            attribution,
            ChangeAttribution::OnlyExcluded { attributed: 0 }
        );
        assert!(attribution.permits_reuse());
    }

    /// A write nested below the cache directory is foreign, not ours.
    ///
    /// The cache writes only direct children. Attributing a deeper record would dismiss changes in
    /// a subdirectory that something else created inside the state directory.
    #[test]
    fn a_write_nested_below_the_cache_directory_is_foreign() {
        let nested_dir = 5555;
        let records = [record(66, nested_dir)];
        let attribution = attribute_changes(&records, &cache_dir());
        assert!(
            !attribution.permits_reuse(),
            "only direct children of the cache directory may be dismissed, got {}",
            attribution.code()
        );
    }

    /// Attribution must key on the reference number, never on the filename.
    ///
    /// Otherwise any process could create `current.json` in a directory it controls and have its
    /// writes dismissed, or make the cache's own writes look foreign.
    #[test]
    fn attribution_ignores_names_entirely() {
        let mut impostor = record(88, 9999);
        impostor.name = "current.json".encode_utf16().collect();
        assert!(
            !attribute_changes(&[impostor], &cache_dir()).permits_reuse(),
            "a file named like a cache file elsewhere on the volume must not be dismissed"
        );

        let mut oddly_named = record(11, CACHE_REF);
        oddly_named.name = "something-else.bin".encode_utf16().collect();
        assert!(
            attribute_changes(&[oddly_named], &cache_dir()).permits_reuse(),
            "membership is decided by parent reference, so the name is irrelevant"
        );
    }

    /// Reference number 0 must not act as a wildcard that attributes unparented records.
    ///
    /// Guards against a default-initialized `ExcludedWriter` silently dismissing every record whose
    /// parent field is zero.
    #[test]
    fn a_zero_reference_does_not_attribute_unrelated_records() {
        let excluded = ExcludedWriter::just(CACHE_REF);
        assert!(
            !attribute_changes(&[record(1, 0)], &excluded).permits_reuse(),
            "a zero parent must not match a real cache directory"
        );
    }

    /// A fully attributed range is promoted back to `Unchanged`, which is what unlocks reuse.
    #[test]
    fn refining_a_cache_only_change_restores_reuse() {
        let verdict = ChangeVerdict::Changed { from: 500, to: 900 };
        let refined = refine_verdict(verdict, &cache_dir(), |from, to| {
            assert_eq!(
                (from, to),
                (500, 900),
                "the read must use the verdict range"
            );
            Ok::<_, ()>(vec![record(11, CACHE_REF)])
        });
        assert_eq!(refined.verdict, ChangeVerdict::Unchanged);
        assert!(refined.permits_reuse());
        assert_eq!(refined.code(), "only_excluded");
    }

    /// A foreign change keeps the original verdict rather than being softened.
    #[test]
    fn refining_a_foreign_change_keeps_refusing_reuse() {
        let verdict = ChangeVerdict::Changed { from: 500, to: 900 };
        let refined = refine_verdict(verdict, &cache_dir(), |_, _| {
            Ok::<_, ()>(vec![record(77, 5000)])
        });
        assert_eq!(
            refined.verdict, verdict,
            "the range must be preserved so a caller can still report it"
        );
        assert!(!refined.permits_reuse());
        assert_eq!(refined.code(), "foreign_change");
    }

    /// A journal read failure must never be mistaken for "nothing changed".
    #[test]
    fn an_unreadable_range_refuses_reuse() {
        let verdict = ChangeVerdict::Changed { from: 500, to: 900 };
        let refined = refine_verdict(verdict, &cache_dir(), |_, _| {
            Err::<Vec<UsnV2Record>, _>(5u32)
        });
        assert!(
            !refined.permits_reuse(),
            "failing to read the history must fail closed"
        );
        assert_eq!(refined.code(), "journal_range_unreadable");
    }

    /// Verdicts that need no explanation must not trigger a journal read at all.
    ///
    /// `MustRescan` in particular has no readable history — reading it would either fail or, worse,
    /// return records from an unrelated journal incarnation.
    #[test]
    fn verdicts_needing_no_history_do_not_read_the_journal() {
        for verdict in [
            ChangeVerdict::Unchanged,
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalWrapped),
            ChangeVerdict::MustRescan(UsnCacheMissReason::JournalChanged),
        ] {
            let refined = refine_verdict(verdict, &cache_dir(), |_, _| -> Result<_, ()> {
                panic!("must not read the journal for {}", verdict.code())
            });
            assert_eq!(refined.verdict, verdict);
            assert!(refined.attribution.is_none());
            assert_eq!(
                refined.permits_reuse(),
                verdict.permits_reuse(),
                "refinement must not change whether {} permits reuse",
                verdict.code()
            );
        }
    }

    /// Only the drive-letter form yields a volume root; anything else has no journal to read.
    #[test]
    fn volume_roots_are_derived_only_from_drive_letters() {
        assert_eq!(
            volume_root_of(Path::new(r"C:\Users\x\AppData")),
            Some(PathBuf::from(r"C:\"))
        );
        assert_eq!(
            volume_root_of(Path::new(r"\\server\share\dir")),
            None,
            "a UNC path has no local volume journal"
        );
        assert_eq!(volume_root_of(Path::new("relative")), None);
    }

    /// An empty exclusion set must dismiss nothing.
    ///
    /// This is the failure mode of a default-constructed or partially-resolved `ExcludedWriter`. It
    /// has to refuse rather than vacuously attribute everything, since "I could not determine which
    /// directories are mine" is the opposite of "nothing else wrote".
    #[test]
    fn an_empty_exclusion_set_attributes_nothing() {
        let empty = ExcludedWriter::default();
        assert!(
            empty.directory_references.is_empty(),
            "the default must not preload a reference"
        );
        assert!(
            !attribute_changes(&[record(11, CACHE_REF)], &empty).permits_reuse(),
            "an unresolved exclusion set must never dismiss a record"
        );
        // An empty range with an empty set is still trivially fine: nothing happened.
        assert!(attribute_changes(&[], &empty).permits_reuse());
    }

    /// A real cache write spans two directories, so both must be excluded together.
    ///
    /// The generation payload lands in `generations/` and the pointer in its parent. Excluding only
    /// one leaves the other looking foreign, which is exactly how a same-volume cache failed to
    /// verify before attribution existed.
    #[test]
    fn a_two_directory_cache_write_is_attributed_as_a_whole() {
        let root_dir = 4242;
        let generations_dir = 4243;
        let records = [
            record(11, generations_dir),       // the generation payload
            record(12, root_dir),              // the current.json pointer
            record(generations_dir, root_dir), // the subdirectory's own metadata
        ];

        let both = ExcludedWriter {
            directory_references: vec![root_dir, generations_dir],
        };
        assert_eq!(
            attribute_changes(&records, &both),
            ChangeAttribution::OnlyExcluded { attributed: 3 },
            "a complete cache write must be fully attributable"
        );

        assert!(
            !attribute_changes(&records, &ExcludedWriter::just(root_dir)).permits_reuse(),
            "excluding only the parent leaves the payload write unexplained"
        );
    }
}
