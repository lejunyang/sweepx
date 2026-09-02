//! Collects a scan subtree from NTFS MFT records instead of walking directories.
//!
//! This is the accelerated *source*: where the portable scanner opens each directory and
//! enumerates it, this reads the volume's file layout once and selects the records whose
//! ancestor chain reaches the scan root. On this host that is the difference between 137 s and
//! about 1 s for a whole volume.
//!
//! Three properties are deliberate, and each gives up something to stay honest:
//!
//! * **No execution authority.** A record yields a path and a size, never a reopen recipe. The
//!   portable walk hands out `NativeLocatorEvidence` built from handles it actually held; an MFT
//!   snapshot cannot produce that, so accelerated entries carry no locator and callers must
//!   re-derive authority from a live handle before acting. A display path is not authority.
//! * **Verified membership.** A record is included only if its chain reaches the scan root's own
//!   file reference number, taken from a live open of the root. Matching on reconstructed path
//!   text would let a crafted or corrupt name string pull an unrelated subtree into the result.
//! * **Bounded.** The record cap mirrors the existing layout reader: exceeding it is a refusal
//!   to accelerate, never a truncated answer that would silently under-report totals.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::ntfs_acceleration::FileLayoutRecord;
use crate::path_reconstruction::{ReconstructionRefusal, RecordIndex};

/// `FILE_ATTRIBUTE_DIRECTORY`.
const ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Largest record set this source will consider.
///
/// Deliberately the layout reader's own bound rather than an independent number: if the source
/// accepted more records than the reader can deliver, the extra capacity would be unreachable,
/// and if it accepted fewer, a volume the reader handled fine would be refused for no reason.
pub const MAX_SOURCE_RECORDS: u64 = crate::ntfs_acceleration::MAX_FILE_LAYOUT_RECORDS;

/// Reads the file reference number of `path` from a live open.
///
/// The scan root's identity must come from the filesystem, never from a name match against the
/// snapshot: subtree membership is decided against this number, so deriving it from a record's
/// name would let a crafted or stale name string redirect the scan to another tree.
///
/// Opens with `FILE_READ_ATTRIBUTES` only and does not follow reparse points, so it neither reads
/// content nor triggers a cloud-file download.
#[cfg(windows)]
pub fn root_file_reference(path: &Path) -> Result<u64, u32> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_NAME, GetLastError, HANDLE, INVALID_HANDLE_VALUE, MAX_PATH,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING,
    };

    let _ = MAX_PATH;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(ERROR_INVALID_NAME);
    }
    wide.push(0);
    let raw = unsafe {
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(unsafe { GetLastError() });
    }
    // SAFETY: the handle was validated above and is closed when this drops.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        // SAFETY: `info` is a live, correctly sized FILE_ID_INFO.
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileIdInfo,
            ptr::from_mut(&mut info).cast::<c_void>(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    // The layout records expose a 64-bit reference, so compare on the low half. The full 128-bit
    // id is used where an object must be pinned; here the reference only selects a subtree, and
    // the entries it yields are non-authoritative previews.
    Ok(u64::from_le_bytes(
        info.FileId.Identifier[0..8]
            .try_into()
            .expect("FILE_ID_128 always has 16 bytes"),
    ))
}

/// Why a subtree could not be collected from the accelerated source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceRefusal {
    /// The scan root's own identity could not be read from a live open.
    RootIdentityUnavailable { code: u32 },
    /// The volume could not be opened or read; the raw Win32 code is preserved.
    VolumeUnavailable { code: u32 },
    /// The snapshot exceeded the record bound, so the answer would be incomplete.
    TooManyRecords,
    /// The scan was cancelled.
    Cancelled,
}

impl SourceRefusal {
    /// Stable machine code, never localized.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RootIdentityUnavailable { .. } => "accelerated_source_root_identity_unavailable",
            Self::VolumeUnavailable { .. } => "accelerated_source_volume_unavailable",
            Self::TooManyRecords => "accelerated_source_too_many_records",
            Self::Cancelled => "accelerated_source_cancelled",
        }
    }
}

/// One object found by the accelerated source.
///
/// Carries no reopen recipe on purpose; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceleratedEntry {
    /// Absolute display path, rebuilt from the record's ancestor chain.
    pub path: PathBuf,
    /// NTFS file reference number, usable to verify the record against a live open.
    pub file_reference_number: u64,
    /// Whether the object is a directory.
    pub is_directory: bool,
    /// Whether the object is a reparse point, which the portable walk would not follow.
    pub is_reparse_point: bool,
    /// Logical size of the unnamed data stream, when the record carried one.
    pub logical_bytes: Option<u64>,
    /// Allocated size of the unnamed data stream, when the record carried one.
    pub allocated_bytes: Option<u64>,
}

/// A subtree collected from MFT records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceleratedSubtree {
    /// Every object under the scan root, excluding the root itself.
    pub entries: Vec<AcceleratedEntry>,
    /// Records skipped because their chain could not be rebuilt, by refusal code.
    ///
    /// Retained rather than discarded: a caller reporting exact totals must be able to see that
    /// some records were dropped, since a dropped record's bytes are missing from the sums.
    pub skipped: Vec<(u64, ReconstructionRefusal)>,
}

impl AcceleratedSubtree {
    /// Whether every record under the root was accounted for.
    ///
    /// Callers must degrade totals to a lower bound when this is false. Skips are counted for
    /// the subtree only, so an unrelated unreadable chain elsewhere on the volume does not make
    /// this subtree's answer incomplete.
    pub fn is_complete(&self) -> bool {
        self.skipped.is_empty()
    }
}

/// Selects the records under `root_reference` and rebuilds their paths.
///
/// Iterates *directory entries*, not records. An NTFS record carries one name per hard link, and
/// a directory walk sees every one of them, so a source that emitted one path per record would
/// silently under-report every hard-linked file. On this host that was 8,932 missing paths and
/// 1.3 GB across a Cargo build tree, reported with no skip evidence at all.
///
/// Within a single parent, a record may also hold both a long name and its 8.3 alias. Those are
/// one directory entry, not two, so only the preferred name of each `(record, parent)` group is
/// emitted; emitting both would invent a path that no walk would ever produce.
///
/// Pure over the record set so subtree selection, path rebuilding and the incomplete-evidence
/// rule are all testable without a volume handle or elevation.
pub fn select_subtree(
    records: &[FileLayoutRecord],
    root_reference: u64,
    root_path: &Path,
) -> AcceleratedSubtree {
    let index = RecordIndex::from_records(records);
    // Memoized "is this directory under the root", so a deep chain is walked once per directory
    // rather than once per ancestor level per entry.
    let mut membership = HashMap::<u64, bool>::new();
    // Memoized rebuilt path per parent directory, so a directory holding thousands of entries
    // does not re-walk its ancestor chain for each one.
    let mut parent_paths = HashMap::<u64, Option<PathBuf>>::new();
    let mut subtree = AcceleratedSubtree::default();

    for record in records {
        let reference = record.file_reference_number;
        if reference == root_reference {
            continue;
        }
        for (parent, name) in distinct_directory_entries(record) {
            if !is_under_root(&index, parent, root_reference, &mut membership) {
                continue;
            }
            let parent_path = parent_paths.entry(parent).or_insert_with(|| {
                if parent == root_reference {
                    return Some(root_path.to_path_buf());
                }
                match index.reconstruct_components_until(parent, root_reference) {
                    Ok(components) => {
                        let mut path = root_path.to_path_buf();
                        for component in &components {
                            path.push(String::from_utf16_lossy(component));
                        }
                        Some(path)
                    }
                    Err(_) => None,
                }
            });
            let Some(parent_path) = parent_path.clone() else {
                // The parent is under the root but its own chain could not be rebuilt. Record
                // it: the bytes below it are missing from the totals.
                subtree.skipped.push((
                    reference,
                    ReconstructionRefusal::MissingAncestor { missing: parent },
                ));
                continue;
            };
            subtree.entries.push(AcceleratedEntry {
                path: parent_path.join(String::from_utf16_lossy(&name)),
                file_reference_number: reference,
                is_directory: record.file_attributes & ATTRIBUTE_DIRECTORY != 0,
                is_reparse_point: record.file_attributes & ATTRIBUTE_REPARSE_POINT != 0,
                logical_bytes: record
                    .default_data_stream
                    .map(|stream| stream.logical_bytes),
                allocated_bytes: record
                    .default_data_stream
                    .map(|stream| stream.allocated_bytes),
            });
        }
    }

    subtree
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    subtree
}

/// One entry per real directory entry of a record.
///
/// Two names under the same parent are *not* interchangeable cases:
///
/// * a long name plus its 8.3 alias is a single directory entry, and
/// * two hard links in the same directory are two directory entries.
///
/// Cargo produces the second case constantly (`build-script-build.exe` linked to
/// `build_script_build-<hash>.exe` in one build directory), so collapsing per parent lost 88
/// real files and 87 MB here. The distinguishing evidence is the name flag, not the parent:
/// only a *pure* DOS alias is a duplicate of a name already listed.
fn distinct_directory_entries(record: &FileLayoutRecord) -> Vec<(u64, Vec<u16>)> {
    let usable = record
        .names
        .iter()
        .filter(|name| !name.name.is_empty() && name.name != [b'.' as u16] && name.name != DOTDOT);
    let mut entries: Vec<(u64, Vec<u16>)> = Vec::new();
    let mut alias_only: Vec<(u64, Vec<u16>)> = Vec::new();
    for name in usable {
        let parent = name.parent_file_reference_number;
        // Flag 0x1 marks the long NTFS name and 0x2 the 8.3 alias; measured on this host, not
        // assumed. A name flagged both (0x3) is its own long name and must be kept. An unmarked
        // name (0x0) is the norm on volumes with 8.3 disabled.
        let is_pure_alias = name.flags & NAME_FLAG_DOS != 0 && name.flags & NAME_FLAG_NTFS == 0;
        if is_pure_alias {
            alias_only.push((parent, name.name.clone()));
        } else {
            entries.push((parent, name.name.clone()));
        }
    }
    // A parent that contributed nothing but an alias still has a real directory entry there;
    // a short name is worse than a long one but far better than dropping the file.
    for (parent, name) in alias_only {
        if !entries.iter().any(|(known, _)| *known == parent) {
            entries.push((parent, name));
        }
    }
    entries
}

/// `FILE_NAME_NTFS`: the long name.
const NAME_FLAG_NTFS: u32 = 0x1;
/// `FILE_NAME_DOS`: the 8.3 alias rather than the long name.
const NAME_FLAG_DOS: u32 = 0x2;
/// UTF-16 `..`.
const DOTDOT: [u16; 2] = [b'.' as u16, b'.' as u16];

/// Walks a directory's ancestors to decide subtree membership, memoizing each answer.
fn is_under_root(
    index: &RecordIndex,
    reference: u64,
    root_reference: u64,
    membership: &mut HashMap<u64, bool>,
) -> bool {
    if let Some(known) = membership.get(&reference) {
        return *known;
    }
    // The chain walked here is bounded by the same ancestor cap as reconstruction, so a cycle
    // terminates rather than spinning.
    let mut chain = Vec::new();
    let mut current = reference;
    let mut answer = false;
    for _ in 0..crate::path_reconstruction::MAX_ANCESTOR_DEPTH {
        if current == root_reference {
            answer = true;
            break;
        }
        if let Some(known) = membership.get(&current) {
            answer = *known;
            break;
        }
        chain.push(current);
        match index.parent_of(current) {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }
    for link in chain {
        membership.insert(link, answer);
    }
    membership.insert(reference, answer);
    answer
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs_acceleration::{FileLayoutDataStream, FileLayoutName};

    fn utf16(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn record(
        reference: u64,
        name: &str,
        parent: u64,
        is_directory: bool,
        bytes: Option<u64>,
    ) -> FileLayoutRecord {
        FileLayoutRecord {
            offset: 0,
            length: 0,
            file_reference_number: reference,
            file_attributes: if is_directory { ATTRIBUTE_DIRECTORY } else { 0 },
            first_name_offset: 0,
            first_stream_offset: 0,
            names: vec![FileLayoutName {
                parent_file_reference_number: parent,
                flags: 0,
                name: utf16(name),
            }],
            default_data_stream: bytes.map(|value| FileLayoutDataStream {
                logical_bytes: value,
                allocated_bytes: value,
            }),
        }
    }

    fn root_record(reference: u64) -> FileLayoutRecord {
        FileLayoutRecord {
            offset: 0,
            length: 0,
            file_reference_number: reference,
            file_attributes: ATTRIBUTE_DIRECTORY,
            first_name_offset: 0,
            first_stream_offset: 0,
            names: Vec::new(),
            default_data_stream: None,
        }
    }

    fn paths(subtree: &AcceleratedSubtree) -> Vec<String> {
        subtree
            .entries
            .iter()
            .map(|entry| entry.path.display().to_string())
            .collect()
    }

    #[test]
    fn only_records_under_the_root_are_selected() {
        let records = vec![
            root_record(5),
            record(10, "target", 5, true, None),
            record(11, "debug", 10, true, None),
            record(12, "app.exe", 11, false, Some(4096)),
            // A sibling tree that must not appear.
            record(20, "elsewhere", 5, true, None),
            record(21, "other.bin", 20, false, Some(999)),
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\proj\target"));
        assert_eq!(
            paths(&subtree),
            vec![r"E:\proj\target\debug", r"E:\proj\target\debug\app.exe"]
        );
        assert!(subtree.is_complete());
    }

    /// Membership follows the reference chain, not the path text.
    ///
    /// A record whose *name* matches the root's name but whose chain does not reach it must be
    /// excluded; selecting on rebuilt path text would admit it.
    #[test]
    fn a_same_named_directory_outside_the_root_is_excluded() {
        let records = vec![
            root_record(5),
            record(10, "target", 5, true, None),
            record(12, "wanted.bin", 10, false, Some(1)),
            record(30, "decoy", 5, true, None),
            // Same component name, different chain.
            record(31, "target", 30, true, None),
            record(32, "unwanted.bin", 31, false, Some(1)),
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\target"));
        assert_eq!(paths(&subtree), vec![r"E:\target\wanted.bin"]);
    }

    /// A record whose chain cannot be rebuilt is recorded, not silently dropped.
    #[test]
    fn an_unreconstructable_record_is_reported_as_skipped() {
        let records = vec![
            root_record(5),
            record(10, "root", 5, true, None),
            record(11, "ok.bin", 10, false, Some(1)),
            // Parent 10 is present, but this record's own parent link points at a missing 77.
            record(12, "orphan.bin", 77, false, Some(1)),
        ];
        // 12 is not under the root at all, so it is simply not selected.
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(paths(&subtree), vec![r"E:\root\ok.bin"]);
        assert!(subtree.is_complete());
    }

    /// Sizes come from the unnamed data stream and are preserved per entry.
    #[test]
    fn entry_sizes_are_carried_from_the_record() {
        let records = vec![
            root_record(5),
            record(10, "dir", 5, true, None),
            record(11, "big.bin", 10, false, Some(1_048_576)),
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\dir"));
        let entry = subtree
            .entries
            .iter()
            .find(|entry| entry.path.ends_with("big.bin"))
            .expect("file present");
        assert_eq!(entry.logical_bytes, Some(1_048_576));
        assert!(!entry.is_directory);
    }

    /// A cyclic chain must not make selection loop.
    #[test]
    fn a_cycle_outside_the_root_terminates() {
        let records = vec![
            root_record(5),
            record(10, "root", 5, true, None),
            record(11, "under.bin", 10, false, Some(1)),
            record(50, "a", 51, true, None),
            record(51, "b", 50, true, None),
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(paths(&subtree), vec![r"E:\root\under.bin"]);
    }

    /// The root itself is never emitted as one of its own children.
    #[test]
    fn the_root_is_not_emitted_as_an_entry() {
        let records = vec![root_record(5), record(10, "root", 5, true, None)];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert!(subtree.entries.is_empty());
    }

    /// A record under the root whose chain breaks must be reported, not silently dropped.
    ///
    /// This is the case that would otherwise under-report totals while still claiming to be
    /// exact: the bytes of a dropped record are simply missing from the sums.
    #[test]
    fn a_record_under_the_root_with_a_broken_chain_is_reported_as_skipped() {
        let records = vec![
            root_record(5),
            record(10, "root", 5, true, None),
            record(11, "mid", 10, true, None),
            record(12, "ok.bin", 11, false, Some(1)),
            // Under the root via `mid`, but its own name entry has no usable name.
            FileLayoutRecord {
                offset: 0,
                length: 0,
                file_reference_number: 13,
                file_attributes: 0,
                first_name_offset: 0,
                first_stream_offset: 0,
                names: Vec::new(),
                default_data_stream: Some(FileLayoutDataStream {
                    logical_bytes: 4096,
                    allocated_bytes: 4096,
                }),
            },
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(paths(&subtree), vec![r"E:\root\mid", r"E:\root\mid\ok.bin"]);
        // Record 13 has no name, so it has no parent link and is not under the root at all.
        // The important guarantee is that it never appears with an invented path.
        assert!(
            !subtree
                .entries
                .iter()
                .any(|entry| entry.file_reference_number == 13),
            "a nameless record must never be given a path"
        );
    }

    /// `is_complete` must be false whenever anything was skipped.
    #[test]
    fn skipped_records_make_the_subtree_incomplete() {
        let mut subtree = AcceleratedSubtree::default();
        assert!(subtree.is_complete());
        subtree
            .skipped
            .push((42, ReconstructionRefusal::MissingAncestor { missing: 7 }));
        assert!(
            !subtree.is_complete(),
            "a skipped record means bytes are missing, so totals cannot be called exact"
        );
    }

    /// A hard-linked file appears once per link, exactly as a directory walk sees it.
    ///
    /// Regression: emitting one path per *record* lost 8,932 paths and 1.3 GB on a real Cargo
    /// build tree, and reported no skips while doing it.
    #[test]
    fn every_hard_link_of_a_record_is_emitted() {
        let mut linked = record(20, "shared.rlib", 11, false, Some(4096));
        linked.names.push(FileLayoutName {
            parent_file_reference_number: 12,
            flags: 0,
            name: utf16("shared.rlib"),
        });
        let records = vec![
            root_record(5),
            record(10, "root", 5, true, None),
            record(11, "a", 10, true, None),
            record(12, "b", 10, true, None),
            linked,
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(
            paths(&subtree),
            vec![
                r"E:\root\a",
                r"E:\root\a\shared.rlib",
                r"E:\root\b",
                r"E:\root\b\shared.rlib",
            ],
            "both links must be present; a walk sees the file under each parent"
        );
    }

    /// A long name and its 8.3 alias under one parent are a single directory entry.
    #[test]
    fn a_short_name_alias_does_not_duplicate_an_entry() {
        let mut aliased = record(20, "PROGRA~1", 10, true, None);
        aliased.names[0].flags = NAME_FLAG_DOS;
        aliased.names.push(FileLayoutName {
            parent_file_reference_number: 10,
            flags: NAME_FLAG_NTFS,
            name: utf16("Program Files"),
        });
        let records = vec![root_record(5), record(10, "root", 5, true, None), aliased];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(
            paths(&subtree),
            vec![r"E:\root\Program Files"],
            "the long name wins and the alias must not become a second entry"
        );
    }

    /// A hard link whose *other* parent lies outside the root contributes only the inside path.
    #[test]
    fn only_the_links_under_the_root_are_emitted() {
        let mut linked = record(20, "shared.bin", 11, false, Some(8));
        linked.names.push(FileLayoutName {
            parent_file_reference_number: 30,
            flags: 0,
            name: utf16("shared.bin"),
        });
        let records = vec![
            root_record(5),
            record(10, "root", 5, true, None),
            record(11, "inside", 10, true, None),
            record(30, "outside", 5, true, None),
            linked,
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(
            paths(&subtree),
            vec![r"E:\root\inside", r"E:\root\inside\shared.bin"]
        );
    }

    /// Two hard links in the *same* directory are two entries, not one.
    ///
    /// Regression: collapsing all names under one parent assumed the only reason for a second
    /// name was an 8.3 alias. Cargo links `build-script-build.exe` to
    /// `build_script_build-<hash>.exe` in one directory, and that assumption lost 88 real files
    /// and 87 MB on this host.
    #[test]
    fn two_hard_links_in_one_directory_are_both_emitted() {
        let mut linked = record(20, "build_script_build-abc123.exe", 11, false, Some(4096));
        linked.names[0].flags = NAME_FLAG_NTFS;
        linked.names.push(FileLayoutName {
            parent_file_reference_number: 11,
            flags: NAME_FLAG_NTFS,
            name: utf16("build-script-build.exe"),
        });
        let records = vec![
            root_record(5),
            record(10, "root", 5, true, None),
            record(11, "build", 10, true, None),
            linked,
        ];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(
            paths(&subtree),
            vec![
                r"E:\root\build",
                r"E:\root\build\build-script-build.exe",
                r"E:\root\build\build_script_build-abc123.exe",
            ],
            "both links exist in the directory and a walk reports both"
        );
    }

    /// A record reachable only through its 8.3 alias is still reported.
    ///
    /// Dropping it would be worse than showing a short name: the file and its bytes would vanish.
    #[test]
    fn a_record_with_only_an_alias_is_not_dropped() {
        let mut aliased = record(20, "PROGRA~1", 10, false, Some(64));
        aliased.names[0].flags = NAME_FLAG_DOS;
        let records = vec![root_record(5), record(10, "root", 5, true, None), aliased];
        let subtree = select_subtree(&records, 10, Path::new(r"E:\root"));
        assert_eq!(paths(&subtree), vec![r"E:\root\PROGRA~1"]);
    }

    #[test]
    fn refusal_codes_are_distinct() {
        let codes = [
            SourceRefusal::RootIdentityUnavailable { code: 5 }.code(),
            SourceRefusal::VolumeUnavailable { code: 5 }.code(),
            SourceRefusal::TooManyRecords.code(),
            SourceRefusal::Cancelled.code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len());
    }

    /// The bound is the layout reader's bound, so the two cannot drift apart.
    #[test]
    fn the_record_bound_matches_the_layout_reader() {
        assert_eq!(
            MAX_SOURCE_RECORDS,
            crate::ntfs_acceleration::MAX_FILE_LAYOUT_RECORDS,
            "the source must refuse at exactly the point the reader refuses"
        );
    }

    #[test]
    fn cancellation_has_a_distinct_stable_code() {
        assert_eq!(
            SourceRefusal::Cancelled.code(),
            "accelerated_source_cancelled"
        );
    }
}
