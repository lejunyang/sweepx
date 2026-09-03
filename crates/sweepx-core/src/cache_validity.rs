//! Deciding whether a stored preview still describes the filesystem it came from.
//!
//! A cached preview is only useful if something can say it is still true. This module captures
//! that evidence when a preview is written and re-checks it when one is read, keeping the platform
//! mechanism (today: the NTFS USN journal) behind a single boundary so the rest of core deals only
//! in "reusable" or "not reusable".
//!
//! Every path fails closed. No evidence, unreadable evidence, evidence of an unknown kind, or
//! evidence that cannot be re-checked all mean *not reusable*, because the cost of being wrong is
//! asymmetric: refusing a valid cache costs one rescan, while accepting an invalid one shows the
//! user sizes for a tree that has since changed.

#[cfg(target_os = "windows")]
use std::collections::BTreeMap;
use sweepx_platform::ScanRoot;

use sweepx_cache::{VALIDITY_KIND_NTFS_USN, VolumeValidityRecord};

/// Why a stored preview may not be reused.
///
/// Carried rather than discarded so the reason can be surfaced and measured: "the volume changed"
/// and "we could not tell whether it changed" look identical from the outside but mean very
/// different things about whether acceleration is working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReuseRefusal {
    /// The generation carries no validity evidence at all.
    NoEvidence,
    /// The evidence names a mechanism this build does not understand.
    UnknownKind(String),
    /// The evidence is structurally unusable, for example a non-numeric position.
    MalformedEvidence,
    /// Evidence could not be re-checked, typically because the volume handle was denied.
    ///
    /// `code` is the OS error where one exists and `0` when the refusal came from the journal
    /// itself rather than from a failed read.
    Unverifiable { code: u32 },
    /// The volume demonstrably changed since capture.
    Changed,
}

impl ReuseRefusal {
    /// A stable machine code, safe to compare across locales.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoEvidence => "no_evidence",
            Self::UnknownKind(_) => "unknown_kind",
            Self::MalformedEvidence => "malformed_evidence",
            Self::Unverifiable { .. } => "unverifiable",
            Self::Changed => "changed",
        }
    }
}

/// Captures per-volume validity evidence for the roots a scan covered.
///
/// Returns an empty vector when nothing could be captured, which is the honest representation of
/// "no evidence" and is what makes the absence fail closed downstream. Capture failure is never an
/// error: a scan that cannot read the journal is still a perfectly good scan, it simply produces a
/// preview that will not be reusable. Reading the journal requires the same elevated volume handle
/// the accelerated reader needs, so an unelevated run captures nothing.
pub fn capture_validity(roots: &[ScanRoot]) -> Vec<VolumeValidityRecord> {
    let _ = roots;
    #[cfg(target_os = "windows")]
    {
        // Keyed by volume: several roots commonly share one volume, and one token per volume is
        // both sufficient and what the comparison expects. A BTreeMap also fixes the order, so the
        // stored bytes do not vary with the order roots happened to be passed in.
        let mut by_volume: BTreeMap<String, VolumeValidityRecord> = BTreeMap::new();
        for root in roots {
            let Some(volume) = volume_key(root.path()) else {
                continue;
            };
            let Ok(token) = sweepx_scanner::read_volume_change_token(root.path()) else {
                continue;
            };
            by_volume.insert(
                volume.clone(),
                VolumeValidityRecord {
                    kind: VALIDITY_KIND_NTFS_USN.to_string(),
                    volume,
                    sequence_id: token.journal_id.to_string(),
                    position: token.next_usn.to_string(),
                },
            );
        }
        by_volume.into_values().collect()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Vec::new()
    }
}

/// Decides whether evidence captured earlier still holds.
///
/// Requires *every* recorded volume to be unchanged. A preview spanning two volumes is only valid
/// if neither moved; treating a partially-valid preview as reusable would show correct sizes for
/// one half of the tree and stale sizes for the other, which is worse than a plain miss because it
/// looks right.
///
/// `state_dir` is the cache's own directory. When a recorded volume also holds the cache, the
/// changed range is read and checked record by record so the cache's own writes do not invalidate
/// it. Passing `None` disables that refinement and keeps the coarse volume-level comparison.
pub fn evaluate_reuse(
    records: &[VolumeValidityRecord],
    state_dir: Option<&std::path::Path>,
) -> Result<(), ReuseRefusal> {
    if records.is_empty() {
        return Err(ReuseRefusal::NoEvidence);
    }
    for record in records {
        if record.kind != VALIDITY_KIND_NTFS_USN {
            return Err(ReuseRefusal::UnknownKind(record.kind.clone()));
        }
        verify_record(record, state_dir)?;
    }
    Ok(())
}

/// The volume a path belongs to, in the form the journal reader accepts.
#[cfg(target_os = "windows")]
fn volume_key(path: &std::path::Path) -> Option<String> {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Some(format!("{}:\\", (letter as char).to_ascii_uppercase()))
            }
            // UNC and device paths have no USN journal reachable this way; no key means no
            // evidence, which fails closed.
            _ => None,
        },
        _ => None,
    }
}

#[cfg(target_os = "windows")]
fn verify_record(
    record: &VolumeValidityRecord,
    state_dir: Option<&std::path::Path>,
) -> Result<(), ReuseRefusal> {
    use sweepx_scanner::{ChangeVerdict, VolumeChangeToken, compare_to_current};

    let (Ok(journal_id), Ok(next_usn)) = (
        record.sequence_id.parse::<u64>(),
        record.position.parse::<i64>(),
    ) else {
        return Err(ReuseRefusal::MalformedEvidence);
    };
    let token = VolumeChangeToken {
        journal_id,
        next_usn,
    };
    let volume = std::path::Path::new(&record.volume);
    // Re-read the volume's current position; a failure here means the journal cannot vouch for
    // anything, not that the volume is unchanged.
    let current = sweepx_scanner::read_volume_journal_bounds(volume)
        .map_err(|code| ReuseRefusal::Unverifiable { code })?;
    match compare_to_current(token, current) {
        ChangeVerdict::Unchanged => Ok(()),
        changed @ ChangeVerdict::Changed { .. } => {
            // The volume moved. If it is the volume holding the cache, the movement may be nothing
            // but the cache writing itself, which must not count as a change to the scanned tree.
            match cache_only_change(changed, volume, state_dir) {
                Some(true) => Ok(()),
                Some(false) => Err(ReuseRefusal::Changed),
                // Attribution was impossible: distinguishable from a real change because nothing is
                // known about what moved.
                None => Err(ReuseRefusal::Changed),
            }
        }
        // A rescan directive means the journal itself cannot vouch for the range, which is not
        // evidence of stability. Treated as unverifiable rather than as "changed" so the two stay
        // distinguishable in reporting.
        ChangeVerdict::MustRescan(_) => Err(ReuseRefusal::Unverifiable { code: 0 }),
    }
}

/// Whether a change on `volume` is entirely attributable to the cache's own directories.
///
/// `Some(true)` means every record in the range came from the cache, `Some(false)` that something
/// else wrote, and `None` that the question could not be answered.
///
/// Only applies when the cache actually lives on the volume in question. When it does not, the cache
/// cannot be the explanation for that volume's activity and the change is real.
#[cfg(target_os = "windows")]
fn cache_only_change(
    verdict: sweepx_scanner::ChangeVerdict,
    volume: &std::path::Path,
    state_dir: Option<&std::path::Path>,
) -> Option<bool> {
    use sweepx_scanner::{ExcludedWriter, refine_verdict, volume_root_of};

    let state_dir = state_dir?;
    // The cache can only explain activity on the volume it is stored on. Comparing volume roots
    // rather than assuming keeps a two-volume setup honest.
    let state_volume = volume_root_of(state_dir)?;
    if !state_volume
        .as_os_str()
        .eq_ignore_ascii_case(volume.as_os_str())
    {
        return Some(false);
    }

    // Every directory a cache write touches must be excluded, or the write looks partly foreign and
    // nothing ever verifies. Identity comes from open handles, never from path text: a USN record
    // carries only a reference number, and matching on names would let any writable location
    // impersonate the cache.
    //
    // A directory that cannot be resolved is skipped rather than guessed. That can only shrink the
    // exclusion set, which makes attribution stricter, never laxer.
    let mut references = Vec::new();
    for directory in cache_write_directories(state_dir) {
        if let Ok(reference) = sweepx_scanner::read_directory_reference(&directory) {
            references.push(reference);
        }
    }
    if references.is_empty() {
        return None;
    }
    let refined = refine_verdict(
        verdict,
        &ExcludedWriter {
            directory_references: references,
        },
        |from, to| sweepx_scanner::read_volume_journal_range(volume, from, to),
    );
    Some(refined.permits_reuse())
}

/// The directories a preview-cache write actually touches.
///
/// Kept next to the attribution logic because it must track [`crate::PREVIEW_GENERATION_POINTER_DIR`]
/// and the cache's internal `generations` subdirectory: the payload is renamed into the latter and
/// the pointer into the former, so both advance the journal on every single write.
#[cfg(target_os = "windows")]
fn cache_write_directories(state_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let preview_root = state_dir.join(crate::PREVIEW_GENERATION_POINTER_DIR);
    let generations = preview_root.join("generations");
    vec![preview_root, generations]
}

/// Without a change-detection mechanism, no evidence can be re-checked.
#[cfg(not(target_os = "windows"))]
fn verify_record(
    _record: &VolumeValidityRecord,
    _state_dir: Option<&std::path::Path>,
) -> Result<(), ReuseRefusal> {
    Err(ReuseRefusal::Unverifiable { code: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, volume: &str, sequence: &str, position: &str) -> VolumeValidityRecord {
        VolumeValidityRecord {
            kind: kind.to_string(),
            volume: volume.to_string(),
            sequence_id: sequence.to_string(),
            position: position.to_string(),
        }
    }

    /// A generation written before validity existed must never be reused.
    #[test]
    fn absent_evidence_is_refused() {
        assert_eq!(evaluate_reuse(&[], None), Err(ReuseRefusal::NoEvidence));
    }

    /// Evidence from a mechanism this build does not know is not evidence.
    ///
    /// Guards forward compatibility: a newer build writing a different kind must degrade to a
    /// rescan here rather than have its token misread as a USN position.
    #[test]
    fn unknown_evidence_kind_is_refused() {
        let records = vec![record("future_mechanism", r"C:\", "1", "2")];
        assert_eq!(
            evaluate_reuse(&records, None),
            Err(ReuseRefusal::UnknownKind("future_mechanism".to_string()))
        );
    }

    /// Refusal codes are stable, distinct and machine-safe.
    #[test]
    fn refusal_codes_are_unique_and_stable() {
        let all = [
            ReuseRefusal::NoEvidence,
            ReuseRefusal::UnknownKind(String::new()),
            ReuseRefusal::MalformedEvidence,
            ReuseRefusal::Unverifiable { code: 5 },
            ReuseRefusal::Changed,
        ];
        let mut codes: Vec<&str> = all.iter().map(ReuseRefusal::code).collect();
        let count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), count, "refusal codes must be distinct");
        assert!(
            codes
                .iter()
                .all(|code| code.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
            "codes must stay snake_case for machine consumers"
        );
    }

    /// A non-numeric position is rejected rather than coerced to a default.
    #[cfg(target_os = "windows")]
    #[test]
    fn malformed_position_is_refused() {
        let records = vec![record(VALIDITY_KIND_NTFS_USN, r"C:\", "1", "not-a-number")];
        assert_eq!(
            evaluate_reuse(&records, None),
            Err(ReuseRefusal::MalformedEvidence)
        );
    }

    /// Paths without a drive letter yield no key, and therefore no evidence.
    #[cfg(target_os = "windows")]
    #[test]
    fn only_drive_letter_paths_produce_a_volume_key() {
        assert_eq!(
            volume_key(std::path::Path::new(r"e:\projects\sweepx")).as_deref(),
            Some(r"E:\"),
            "the key must be normalized so two spellings of one volume agree"
        );
        assert_eq!(
            volume_key(std::path::Path::new(r"\\server\share\dir")),
            None
        );
    }
}
