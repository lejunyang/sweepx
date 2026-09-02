//! Rebuilds directory paths from MFT layout records.
//!
//! A layout record names its parent by reference number, not by path, so a path exists only as
//! a chain walked from a record up to the volume root. The walk is the part of accelerated
//! scanning that cannot be trusted on structure alone: a corrupt or racing snapshot can present
//! a cycle, a missing parent, or a record whose parent is a plain file, and each of those must
//! produce a refusal rather than a plausible-looking path.
//!
//! Everything here is a pure function over already-parsed records. That is deliberate: reading
//! the MFT needs elevation, but deciding what a set of records means does not, so the failure
//! modes above are unit-testable on an ordinary account and only the input has to come from a
//! privileged read.
//!
//! A reconstructed path is **reporting data only**. It never grants filesystem authority; an
//! accelerated record still has to pass `accelerated_verification` before it can affect a
//! result, and any destructive step re-derives authority from a live handle.

use std::collections::HashMap;

use crate::ntfs_acceleration::FileLayoutRecord;

/// Upper bound on ancestor links followed for one record.
///
/// A cycle is already rejected by the visited-set check below; this is the second, cheaper
/// guard against a pathological but acyclic chain, and it bounds work per record even when the
/// snapshot is adversarial. NTFS paths are limited well below this in practice.
pub const MAX_ANCESTOR_DEPTH: usize = 512;

/// Why a record could not be given a path.
///
/// Each variant is a refusal, never a partially-built path: emitting "as much of the path as we
/// could determine" would produce a string that looks addressable but names the wrong object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconstructionRefusal {
    /// An ancestor reference was not present in the snapshot.
    ///
    /// Ordinary during incremental reads, where a parent may live on a page not yet read.
    MissingAncestor { missing: u64 },
    /// The ancestor chain revisited a record, so the snapshot describes a cycle.
    CyclicChain { repeated: u64 },
    /// The chain exceeded [`MAX_ANCESTOR_DEPTH`] without reaching the root.
    ChainTooDeep,
    /// An ancestor exists but is not a directory, so it cannot contain the child.
    AncestorNotADirectory { reference: u64 },
    /// The record carries no usable name.
    ///
    /// Includes the volume root, whose NTFS name is `.` and is deliberately not treated as a
    /// path component.
    NoUsableName,
}

impl ReconstructionRefusal {
    /// Stable machine code for structured output. Never localized.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingAncestor { .. } => "reconstruction_missing_ancestor",
            Self::CyclicChain { .. } => "reconstruction_cyclic_chain",
            Self::ChainTooDeep => "reconstruction_chain_too_deep",
            Self::AncestorNotADirectory { .. } => "reconstruction_ancestor_not_a_directory",
            Self::NoUsableName => "reconstruction_no_usable_name",
        }
    }

    /// Whether the refusal is expected while reading a snapshot incrementally.
    ///
    /// A missing ancestor usually means "not read yet". A cycle or a file acting as a directory
    /// means the snapshot is inconsistent and must not be trusted as a whole.
    pub const fn is_expected_during_incremental_reads(&self) -> bool {
        matches!(self, Self::MissingAncestor { .. })
    }
}

/// UTF-16 attribute bit marking a directory (`FILE_ATTRIBUTE_DIRECTORY`).
const ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// `FILE_LAYOUT_NAME_ENTRY_NTFS` — the name is the full-length NTFS name.
///
/// The bit values here were **measured**, not assumed. An earlier attempt guessed the opposite
/// assignment, and because both names resolve to the same object the mistake was invisible to
/// every resolution check — the cross-check numbers did not move at all. Observed on `C:`:
/// `flags=0x1` accompanies `ClickToRun` while `flags=0x2` accompanies `CLICKT~1`.
const NAME_ENTRY_NTFS: u32 = 0x0000_0001;
/// `FILE_LAYOUT_NAME_ENTRY_DOS` — the name is the 8.3 short name.
const NAME_ENTRY_DOS: u32 = 0x0000_0002;

/// Chooses the name to display for a record.
///
/// NTFS may store both an 8.3 short name and a long name for the same object, and the layout
/// record lists them in on-disk order, which is not preference order. Taking the first name
/// rebuilt `C:\PROGRA~1\COMMON~1\MICROS~1\VSTO` where the OS reports
/// `C:\Program Files\Common Files\microsoft shared\VSTO` — a path that still resolves, so no
/// resolution test would have caught it, but that is wrong to show a user and wrong to match
/// against rules written in terms of real directory names.
///
/// Preference is explicit rather than positional: a name flagged NTFS wins, a name flagged only
/// DOS is used solely when nothing better exists, and an unflagged name is treated as ordinary.
/// Unflagged names are the common case on volumes without 8.3 generation — `E:` reported
/// `flags=0x0` for 23483 of 23494 names — so they must not be treated as second class.
fn preferred_name(
    names: &[crate::ntfs_acceleration::FileLayoutName],
) -> Option<&crate::ntfs_acceleration::FileLayoutName> {
    names
        .iter()
        .find(|name| name.flags & NAME_ENTRY_NTFS != 0)
        .or_else(|| names.iter().find(|name| name.flags & NAME_ENTRY_DOS == 0))
        .or_else(|| names.first())
}

/// An index over layout records, keyed by file reference number.
///
/// Built once per snapshot so each reconstruction is a chain of hash lookups rather than a
/// rescan. Holds only what the walk needs, so it does not pin whole pages in memory.
#[derive(Debug, Default)]
pub struct RecordIndex {
    entries: HashMap<u64, IndexedRecord>,
}

#[derive(Debug, Clone)]
struct IndexedRecord {
    /// First usable name, as UTF-16 units. `None` for the root or a nameless record.
    name: Option<Vec<u16>>,
    parent: Option<u64>,
    is_directory: bool,
}

impl RecordIndex {
    /// Indexes a batch of parsed layout records.
    ///
    /// When a record carries several names, the long NTFS name is preferred over an 8.3 short
    /// name; see [`preferred_name`]. Among equally-preferred names — which is what hard links
    /// produce — the first wins. That is a reporting choice, not an identity one: hard links
    /// give one object multiple equally valid paths, and identity is carried by the reference
    /// number rather than by whichever name is displayed.
    pub fn from_records(records: &[FileLayoutRecord]) -> Self {
        let mut entries = HashMap::with_capacity(records.len());
        for record in records {
            let chosen = preferred_name(&record.names);
            entries.insert(
                record.file_reference_number,
                IndexedRecord {
                    name: chosen.map(|name| name.name.clone()),
                    parent: chosen.map(|name| name.parent_file_reference_number),
                    is_directory: record.file_attributes & ATTRIBUTE_DIRECTORY != 0,
                },
            );
        }
        Self { entries }
    }

    /// Number of indexed records.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index holds no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Parent reference of an indexed record, when it has a usable name.
    ///
    /// Exposed so subtree selection can walk ancestry without rebuilding path text, which keeps
    /// membership a question about reference numbers rather than about strings.
    pub fn parent_of(&self, reference: u64) -> Option<u64> {
        self.entries.get(&reference).and_then(|entry| entry.parent)
    }

    /// Rebuilds path components relative to `stop_at`, exclusive.
    ///
    /// Used when the caller already knows the absolute path of an ancestor (the scan root) and
    /// needs only the components below it. Stopping at a known ancestor rather than the volume
    /// root also means a scan of a subtree does not depend on records for directories above it,
    /// which a partial layout read may not have supplied.
    pub fn reconstruct_components_until(
        &self,
        reference: u64,
        stop_at: u64,
    ) -> Result<Vec<Vec<u16>>, ReconstructionRefusal> {
        self.walk(reference, Some(stop_at))
    }

    /// Rebuilds the path components for `reference`, root-first, excluding the volume root.
    ///
    /// Returns UTF-16 components so a name that is not valid Unicode survives without being
    /// replaced by U+FFFD; lossy conversion belongs at the display boundary, not here, since a
    /// mangled name must never be mistaken for an addressable one.
    pub fn reconstruct_components(
        &self,
        reference: u64,
    ) -> Result<Vec<Vec<u16>>, ReconstructionRefusal> {
        self.walk(reference, None)
    }

    fn walk(
        &self,
        reference: u64,
        stop_at: Option<u64>,
    ) -> Result<Vec<Vec<u16>>, ReconstructionRefusal> {
        let start = self
            .entries
            .get(&reference)
            .ok_or(ReconstructionRefusal::MissingAncestor { missing: reference })?;
        let Some(start_name) = start.name.as_ref() else {
            return Err(ReconstructionRefusal::NoUsableName);
        };

        let mut components = vec![start_name.clone()];
        // The visited set is what makes a cycle terminate; the depth cap alone would still walk
        // MAX_ANCESTOR_DEPTH links before noticing.
        let mut visited = std::collections::BTreeSet::new();
        visited.insert(reference);

        let mut current = start.parent;
        while let Some(parent_reference) = current {
            // Stop before consuming the caller's known ancestor: its name belongs to the path
            // the caller already holds, so including it would duplicate a component.
            if stop_at == Some(parent_reference) {
                break;
            }
            if components.len() > MAX_ANCESTOR_DEPTH {
                return Err(ReconstructionRefusal::ChainTooDeep);
            }
            if !visited.insert(parent_reference) {
                return Err(ReconstructionRefusal::CyclicChain {
                    repeated: parent_reference,
                });
            }
            let parent = self.entries.get(&parent_reference).ok_or(
                ReconstructionRefusal::MissingAncestor {
                    missing: parent_reference,
                },
            )?;
            if !parent.is_directory {
                // A file cannot contain a child. Continuing would yield a path that reads
                // normally while naming something that does not exist.
                return Err(ReconstructionRefusal::AncestorNotADirectory {
                    reference: parent_reference,
                });
            }
            match parent.name.as_ref() {
                // The root has no composable name, so the chain is complete here.
                None => break,
                Some(name) => components.push(name.clone()),
            }
            current = parent.parent;
            // A record that is its own parent terminates the chain at the root in NTFS; the
            // visited set above catches it on the next iteration if it is a genuine cycle.
            if current == Some(parent_reference) {
                break;
            }
        }

        components.reverse();
        Ok(components)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs_acceleration::{FileLayoutName, FileLayoutRecord};

    fn utf16(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn record(reference: u64, name: Option<(&str, u64)>, is_directory: bool) -> FileLayoutRecord {
        FileLayoutRecord {
            offset: 0,
            length: 0,
            file_reference_number: reference,
            file_attributes: if is_directory { ATTRIBUTE_DIRECTORY } else { 0 },
            first_name_offset: 0,
            first_stream_offset: 0,
            names: name
                .map(|(text, parent)| {
                    vec![FileLayoutName {
                        parent_file_reference_number: parent,
                        flags: 0,
                        name: utf16(text),
                    }]
                })
                .unwrap_or_default(),
            default_data_stream: None,
        }
    }

    /// The root is nameless here, mirroring how `.` is excluded during parsing.
    fn root(reference: u64) -> FileLayoutRecord {
        record(reference, None, true)
    }

    fn joined(components: &[Vec<u16>]) -> String {
        components
            .iter()
            .map(|part| String::from_utf16_lossy(part))
            .collect::<Vec<_>>()
            .join("\\")
    }

    #[test]
    fn a_nested_chain_rebuilds_root_first() {
        let index = RecordIndex::from_records(&[
            root(5),
            record(6, Some(("Projects", 5)), true),
            record(7, Some(("sweepx", 6)), true),
            record(8, Some(("Cargo.toml", 7)), false),
        ]);
        let components = index.reconstruct_components(8).expect("chain rebuilds");
        assert_eq!(joined(&components), "Projects\\sweepx\\Cargo.toml");
    }

    #[test]
    fn a_child_of_the_root_has_a_single_component() {
        let index =
            RecordIndex::from_records(&[root(5), record(6, Some(("pagefile.sys", 5)), false)]);
        assert_eq!(
            joined(&index.reconstruct_components(6).unwrap()),
            "pagefile.sys"
        );
    }

    /// A cycle must be refused rather than walked until the depth cap.
    #[test]
    fn a_cyclic_chain_is_refused() {
        let index = RecordIndex::from_records(&[
            record(10, Some(("a", 11)), true),
            record(11, Some(("b", 10)), true),
        ]);
        assert_eq!(
            index.reconstruct_components(10),
            Err(ReconstructionRefusal::CyclicChain { repeated: 10 })
        );
    }

    /// A record whose parent is absent is refused, and marked as ordinary for partial reads.
    #[test]
    fn a_missing_ancestor_is_refused_but_expected_during_incremental_reads() {
        let index = RecordIndex::from_records(&[record(20, Some(("orphan.txt", 99)), false)]);
        let refusal = index.reconstruct_components(20).unwrap_err();
        assert_eq!(
            refusal,
            ReconstructionRefusal::MissingAncestor { missing: 99 }
        );
        assert!(refusal.is_expected_during_incremental_reads());
    }

    /// A file cannot be an ancestor; this is the case that would otherwise yield a
    /// normal-looking path naming an object that does not exist.
    #[test]
    fn a_file_acting_as_an_ancestor_is_refused() {
        let index = RecordIndex::from_records(&[
            root(5),
            record(6, Some(("notes.txt", 5)), false),
            record(7, Some(("child.bin", 6)), false),
        ]);
        let refusal = index.reconstruct_components(7).unwrap_err();
        assert_eq!(
            refusal,
            ReconstructionRefusal::AncestorNotADirectory { reference: 6 }
        );
        assert!(
            !refusal.is_expected_during_incremental_reads(),
            "an inconsistent snapshot must not be treated as routine churn"
        );
    }

    #[test]
    fn the_root_itself_has_no_usable_name() {
        let index = RecordIndex::from_records(&[root(5)]);
        assert_eq!(
            index.reconstruct_components(5),
            Err(ReconstructionRefusal::NoUsableName)
        );
    }

    /// A chain longer than the cap is refused rather than walked indefinitely.
    #[test]
    fn an_overlong_chain_is_refused() {
        let mut records = vec![root(0)];
        // Each record's parent is the previous one, forming an acyclic chain past the cap.
        for reference in 1..(MAX_ANCESTOR_DEPTH as u64 + 10) {
            records.push(record(reference, Some(("d", reference - 1)), true));
        }
        let deepest = MAX_ANCESTOR_DEPTH as u64 + 9;
        assert_eq!(
            records.last().unwrap().file_reference_number,
            deepest,
            "the fixture must actually exceed the cap"
        );
        assert_eq!(
            RecordIndex::from_records(&records).reconstruct_components(deepest),
            Err(ReconstructionRefusal::ChainTooDeep)
        );
    }

    /// Names that are not valid Unicode must survive reconstruction unchanged.
    #[test]
    fn an_unpaired_surrogate_name_is_preserved_losslessly() {
        let mut lone = vec![0xD800u16];
        lone.extend(utf16("tail"));
        let index = RecordIndex::from_records(&[
            root(5),
            FileLayoutRecord {
                offset: 0,
                length: 0,
                file_reference_number: 6,
                file_attributes: 0,
                first_name_offset: 0,
                first_stream_offset: 0,
                names: vec![FileLayoutName {
                    parent_file_reference_number: 5,
                    flags: 0,
                    name: lone.clone(),
                }],
                default_data_stream: None,
            },
        ]);
        let components = index.reconstruct_components(6).expect("rebuilds");
        assert_eq!(
            components,
            vec![lone],
            "reconstruction must not replace unpaired surrogates with U+FFFD"
        );
    }

    /// A record that names itself as parent terminates instead of looping.
    #[test]
    fn a_self_parenting_record_terminates() {
        let index = RecordIndex::from_records(&[record(5, Some(("weird", 5)), true)]);
        let refusal = index.reconstruct_components(5).unwrap_err();
        assert_eq!(
            refusal,
            ReconstructionRefusal::CyclicChain { repeated: 5 },
            "a self-referencing parent is a cycle, not a root"
        );
    }

    /// The long NTFS name must win even when the short name is listed first on disk.
    ///
    /// Regression test for a defect only an elevated cross-check could find: taking the first
    /// name rebuilt `C:\PROGRA~1\COMMON~1\VSTO` while the OS reports
    /// `C:\Program Files\Common Files\VSTO`. Both resolve, so nothing failed and no
    /// resolution-based test could notice.
    ///
    /// The literals below are the **measured** on-disk values (`0x2` on `CLICKT~1`, `0x1` on
    /// `ClickToRun`), written out rather than referencing the named constants on purpose: the
    /// first version of this test used the constants and kept passing while those constants
    /// were defined backwards.
    #[test]
    fn the_long_name_is_preferred_over_an_eight_dot_three_short_name() {
        let dos_first = FileLayoutRecord {
            offset: 0,
            length: 0,
            file_reference_number: 6,
            file_attributes: ATTRIBUTE_DIRECTORY,
            first_name_offset: 0,
            first_stream_offset: 0,
            names: vec![
                FileLayoutName {
                    parent_file_reference_number: 5,
                    flags: 0x2,
                    name: utf16("PROGRA~1"),
                },
                FileLayoutName {
                    parent_file_reference_number: 5,
                    flags: 0x1,
                    name: utf16("Program Files"),
                },
            ],
            default_data_stream: None,
        };
        let index = RecordIndex::from_records(&[root(5), dos_first]);
        assert_eq!(
            joined(&index.reconstruct_components(6).unwrap()),
            "Program Files",
            "the displayed name must be the long NTFS name, not the 8.3 alias"
        );
    }

    /// A record with only a short name still yields that name rather than nothing.
    #[test]
    fn a_short_name_is_used_when_it_is_the_only_name() {
        let only_dos = FileLayoutRecord {
            offset: 0,
            length: 0,
            file_reference_number: 6,
            file_attributes: 0,
            first_name_offset: 0,
            first_stream_offset: 0,
            names: vec![FileLayoutName {
                parent_file_reference_number: 5,
                flags: 0x2,
                name: utf16("LEGACY~1.TXT"),
            }],
            default_data_stream: None,
        };
        let index = RecordIndex::from_records(&[root(5), only_dos]);
        assert_eq!(
            joined(&index.reconstruct_components(6).unwrap()),
            "LEGACY~1.TXT",
            "refusing a record that has only a short name would lose it entirely"
        );
    }

    /// Unflagged names are the norm on volumes without 8.3 generation and must be usable.
    ///
    /// Measured: `E:` reported `flags=0x0` for 23483 of 23494 names. Treating an unflagged name
    /// as "not the NTFS name" would break reconstruction on such a volume entirely.
    #[test]
    fn an_unflagged_name_is_used_normally() {
        let index = RecordIndex::from_records(&[
            root(5),
            record(6, Some(("target", 5)), true),
            record(7, Some(("debug", 6)), true),
        ]);
        assert_eq!(
            joined(&index.reconstruct_components(7).unwrap()),
            "target\\debug"
        );
    }

    #[test]
    fn refusal_codes_are_distinct() {
        let codes = [
            ReconstructionRefusal::MissingAncestor { missing: 1 }.code(),
            ReconstructionRefusal::CyclicChain { repeated: 1 }.code(),
            ReconstructionRefusal::ChainTooDeep.code(),
            ReconstructionRefusal::AncestorNotADirectory { reference: 1 }.code(),
            ReconstructionRefusal::NoUsableName.code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }
}
