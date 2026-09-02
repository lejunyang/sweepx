use std::mem::size_of;
use std::path::Path;

use sweepx_platform::CancellationToken;

/// Upper bound for one NTFS layout page. Runtime I/O uses the same cap after native qualification.
pub const FILE_LAYOUT_PAGE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum file records consumed before the fast path must fall back to directory traversal.
pub const MAX_FILE_LAYOUT_RECORDS: u64 = 10_000_000;
/// Fixed bytes before the variable UTF-16 name in a version-2 USN record.
pub const USN_V2_FIXED_BYTES: usize = 60;
/// Maximum USN records accepted for one cache-validity check.
pub const MAX_USN_RECORDS: usize = 10_000_000;
/// Maximum pages accepted from either native volume API before falling back.
pub const MAX_NATIVE_PAGES: usize = 16_384;

const FILE_LAYOUT_OUTPUT_BYTES: usize = 16;
const FILE_LAYOUT_ENTRY_BYTES: usize = 40;
const FILE_LAYOUT_NAME_HEADER_BYTES: usize = 24;
const STREAM_LAYOUT_HEADER_BYTES: usize = 48;
const SUPPORTED_FILE_LAYOUT_VERSION: u32 = 1;
const SUPPORTED_STREAM_LAYOUT_VERSION: u32 = 1;
const SUPPORTED_USN_MAJOR_VERSION: u16 = 2;
const NTFS_DATA_ATTRIBUTE: u32 = 0x80;
const MAX_NAME_CHAIN_LENGTH: usize = 4096;
const MAX_STREAM_CHAIN_LENGTH: usize = 4096;

/// A validated file record boundary in one `FSCTL_QUERY_FILE_LAYOUT` output page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLayoutRecord {
    pub offset: usize,
    pub length: usize,
    pub file_reference_number: u64,
    pub file_attributes: u32,
    pub first_name_offset: u32,
    pub first_stream_offset: u32,
    pub names: Vec<FileLayoutName>,
    pub default_data_stream: Option<FileLayoutDataStream>,
}

/// One validated long or short name linked to an NTFS file record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLayoutName {
    pub parent_file_reference_number: u64,
    pub flags: u32,
    pub name: Vec<u16>,
}

/// Logical and allocated byte counts for the unnamed NTFS `$DATA` stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileLayoutDataStream {
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

/// A validated USN v2 change record. Names stay encoded as UTF-16 units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnV2Record {
    pub file_reference_number: u64,
    pub parent_file_reference_number: u64,
    pub usn: i64,
    pub reason: u32,
    pub file_attributes: u32,
    pub name: Vec<u16>,
}

/// Captured USN journal bounds used to validate whether a cache cursor is still readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsnJournalBounds {
    pub journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub lowest_valid_usn: i64,
}

/// Outcome of validating one previously captured USN cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnCursorDecision {
    ReadFrom(i64),
    CacheMiss(UsnCacheMissReason),
}

/// Stable reasons why incremental reuse must fall back to a complete scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsnCacheMissReason {
    JournalChanged,
    JournalWrapped,
    CursorAhead,
    InvalidBounds,
}

/// Read-only capability probe result for the NTFS acceleration path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsAccelerationProbe {
    Available {
        layout_records: u64,
        journal: UsnJournalBounds,
    },
    Fallback(NtfsAccelerationFallback),
}

/// Stable reason why the portable handle-relative scanner must remain authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsAccelerationFallback {
    UnsupportedPlatform,
    UnsupportedRoot,
    UnsupportedFilesystem,
    AccessDeniedOrUnavailable,
    InvalidNativeData,
    ResourceLimit,
    Cancelled,
    /// The process is not elevated, so the volume handle both accelerators need
    /// cannot be opened at all.
    ///
    /// Distinguished from [`Self::AccessDeniedOrUnavailable`] because the causes call
    /// for different responses: this one is fully explained by the current privilege
    /// level and resolves if the user runs elevated, whereas a generic denial may come
    /// from volume state, a filter driver, or policy. Collapsing them would tell a
    /// normal user that something is broken when the behavior is exactly as designed.
    NotElevated,
}

/// Probes the native NTFS layout and USN sources without changing filesystem or journal state.
///
/// Privilege is checked first, and deliberately so. Both `FSCTL_QUERY_FILE_LAYOUT` and
/// `FSCTL_QUERY_USN_JOURNAL` require a volume handle that an unelevated token cannot
/// obtain: measured on Windows, requesting `FILE_READ_DATA` or `GENERIC_READ` on
/// `\\.\C:` fails with `ERROR_ACCESS_DENIED`, while an attribute-only handle does open
/// but then rejects both control codes with `ERROR_INVALID_FUNCTION`. Since no reduced
/// access level works, asking the token up front turns an inevitable failure into an
/// accurate reason without touching the volume at all.
#[cfg(windows)]
pub fn probe_ntfs_acceleration(root: &Path, cancel: &CancellationToken) -> NtfsAccelerationProbe {
    if cancel.is_cancelled() {
        return NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::Cancelled);
    }
    // Only a definite `Elevated` proceeds: an unreadable token must not send the probe
    // down a path whose prerequisite could not be confirmed.
    use sweepx_platform::PrivilegeProvider as _;
    if !crate::WindowsPrivilegeProvider::new()
        .observe()
        .level
        .grants_elevated_capability()
    {
        return NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::NotElevated);
    }
    native::probe(root, cancel)
}

/// Reports the portable fallback on non-Windows hosts.
#[cfg(not(windows))]
pub fn probe_ntfs_acceleration(_root: &Path, cancel: &CancellationToken) -> NtfsAccelerationProbe {
    if cancel.is_cancelled() {
        NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::Cancelled)
    } else {
        NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::UnsupportedPlatform)
    }
}

/// Validates a cached USN cursor without treating a missing history range as reusable.
pub fn validate_usn_cursor(
    expected_journal_id: u64,
    cursor: i64,
    current: UsnJournalBounds,
) -> UsnCursorDecision {
    if current.first_usn < 0
        || current.lowest_valid_usn < 0
        || current.next_usn < 0
        || current.first_usn > current.next_usn
        || current.lowest_valid_usn > current.next_usn
    {
        return UsnCursorDecision::CacheMiss(UsnCacheMissReason::InvalidBounds);
    }
    if expected_journal_id != current.journal_id {
        return UsnCursorDecision::CacheMiss(UsnCacheMissReason::JournalChanged);
    }
    if cursor < current.first_usn || cursor < current.lowest_valid_usn {
        return UsnCursorDecision::CacheMiss(UsnCacheMissReason::JournalWrapped);
    }
    if cursor > current.next_usn {
        return UsnCursorDecision::CacheMiss(UsnCacheMissReason::CursorAhead);
    }
    UsnCursorDecision::ReadFrom(cursor)
}

/// Parses one bounded NTFS layout page without dereferencing kernel-provided offsets.
pub fn parse_file_layout_page(bytes: &[u8]) -> Result<Vec<FileLayoutRecord>, &'static str> {
    if bytes.len() < FILE_LAYOUT_OUTPUT_BYTES {
        return Err("layout_header_truncated");
    }
    let count = read_u32(bytes, 0)? as usize;
    if count == 0 || count as u64 > MAX_FILE_LAYOUT_RECORDS {
        return Err("layout_record_count_invalid");
    }
    let mut offset = read_u32(bytes, 4)? as usize;
    if offset < FILE_LAYOUT_OUTPUT_BYTES {
        return Err("layout_first_record_overlaps_header");
    }
    let mut records = Vec::with_capacity(count.min(4096));
    for index in 0..count {
        let end = offset
            .checked_add(FILE_LAYOUT_ENTRY_BYTES)
            .filter(|end| *end <= bytes.len())
            .ok_or("layout_record_truncated")?;
        let version = read_u32(bytes, offset)?;
        if version != SUPPORTED_FILE_LAYOUT_VERSION {
            return Err("layout_version_unsupported");
        }
        let next = read_u32(bytes, offset + 4)? as usize;
        let record_end = if index + 1 == count {
            if next != 0 {
                return Err("layout_last_record_has_next");
            }
            bytes.len()
        } else {
            if next < FILE_LAYOUT_ENTRY_BYTES {
                return Err("layout_next_record_overlaps_current");
            }
            offset
                .checked_add(next)
                .filter(|next| *next <= bytes.len())
                .ok_or("layout_next_record_out_of_bounds")?
        };
        for relative in [read_u32(bytes, offset + 24)?, read_u32(bytes, offset + 28)?] {
            if relative != 0
                && ((relative as usize) < FILE_LAYOUT_ENTRY_BYTES
                    || offset
                        .checked_add(relative as usize)
                        .is_none_or(|absolute| absolute >= record_end))
            {
                return Err("layout_child_offset_out_of_bounds");
            }
        }
        records.push(FileLayoutRecord {
            offset,
            length: record_end - offset,
            file_attributes: read_u32(bytes, offset + 12)?,
            file_reference_number: read_u64(bytes, offset + 16)?,
            first_name_offset: read_u32(bytes, offset + 24)?,
            first_stream_offset: read_u32(bytes, offset + 28)?,
            names: parse_layout_names(bytes, offset, record_end, read_u32(bytes, offset + 24)?)?,
            default_data_stream: parse_default_data_stream(
                bytes,
                offset,
                record_end,
                read_u32(bytes, offset + 28)?,
            )?,
        });
        if end > record_end {
            return Err("layout_record_overlaps_next");
        }
        offset = record_end;
    }
    Ok(records)
}

fn parse_layout_names(
    bytes: &[u8],
    file_offset: usize,
    record_end: usize,
    first_relative: u32,
) -> Result<Vec<FileLayoutName>, &'static str> {
    if first_relative == 0 {
        return Ok(Vec::new());
    }
    let mut offset = file_offset
        .checked_add(first_relative as usize)
        .filter(|offset| *offset < record_end)
        .ok_or("layout_name_offset_out_of_bounds")?;
    let mut names = Vec::new();
    for _ in 0..MAX_NAME_CHAIN_LENGTH {
        if offset
            .checked_add(FILE_LAYOUT_NAME_HEADER_BYTES)
            .is_none_or(|end| end > record_end)
        {
            return Err("layout_name_header_truncated");
        }
        let next = read_u32(bytes, offset)? as usize;
        let flags = read_u32(bytes, offset + 4)?;
        let parent_file_reference_number = read_u64(bytes, offset + 8)?;
        let name_bytes = read_u32(bytes, offset + 16)? as usize;
        if !name_bytes.is_multiple_of(2) {
            return Err("layout_name_length_invalid");
        }
        let name_start = offset + FILE_LAYOUT_NAME_HEADER_BYTES;
        let name_end = name_start
            .checked_add(name_bytes)
            .filter(|end| *end <= record_end)
            .ok_or("layout_name_truncated")?;
        let (units, remainder) = bytes[name_start..name_end].as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        let name = units
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect::<Vec<_>>();
        if name.is_empty() || name.contains(&0) || name == [b'.' as u16, b'.' as u16] {
            return Err("layout_name_invalid");
        }
        // NTFS names the volume root record "." — a real on-disk name, not corruption.
        // Rejecting it discarded the entire first layout page (measured: 17409 valid records
        // thrown away because of one legitimate record), which made the whole accelerator
        // look unsupported. It is accepted here but deliberately not emitted as a name,
        // because composing "." into a reconstructed path would resolve to the wrong
        // directory. ".." above stays rejected unconditionally: it is never a real NTFS
        // filename, so seeing one means either corruption or a traversal attempt, and both
        // must fail closed rather than become a path component.
        let composable = name != [b'.' as u16];
        if composable {
            names.push(FileLayoutName {
                parent_file_reference_number,
                flags,
                name,
            });
        }
        if next == 0 {
            return Ok(names);
        }
        if next < FILE_LAYOUT_NAME_HEADER_BYTES + name_bytes {
            return Err("layout_name_chain_overlaps");
        }
        offset = offset
            .checked_add(next)
            .filter(|offset| *offset < record_end)
            .ok_or("layout_name_chain_out_of_bounds")?;
    }
    Err("layout_name_chain_limit_exceeded")
}

fn parse_default_data_stream(
    bytes: &[u8],
    file_offset: usize,
    record_end: usize,
    first_relative: u32,
) -> Result<Option<FileLayoutDataStream>, &'static str> {
    if first_relative == 0 {
        return Ok(None);
    }
    let mut offset = file_offset
        .checked_add(first_relative as usize)
        .filter(|offset| *offset < record_end)
        .ok_or("layout_stream_offset_out_of_bounds")?;
    for _ in 0..MAX_STREAM_CHAIN_LENGTH {
        if offset
            .checked_add(STREAM_LAYOUT_HEADER_BYTES)
            .is_none_or(|end| end > record_end)
        {
            return Err("layout_stream_header_truncated");
        }
        if read_u32(bytes, offset)? != SUPPORTED_STREAM_LAYOUT_VERSION {
            return Err("layout_stream_version_unsupported");
        }
        let next = read_u32(bytes, offset + 4)? as usize;
        let allocated = read_i64(bytes, offset + 16)?;
        let logical = read_i64(bytes, offset + 24)?;
        let attribute_type = read_u32(bytes, offset + 36)?;
        let identifier_bytes = read_u32(bytes, offset + 44)? as usize;
        if !identifier_bytes.is_multiple_of(2)
            || offset
                .checked_add(STREAM_LAYOUT_HEADER_BYTES + identifier_bytes)
                .is_none_or(|end| end > record_end)
        {
            return Err("layout_stream_identifier_invalid");
        }
        if attribute_type == NTFS_DATA_ATTRIBUTE && identifier_bytes == 0 {
            if allocated < 0 || logical < 0 {
                return Err("layout_stream_size_negative");
            }
            return Ok(Some(FileLayoutDataStream {
                logical_bytes: logical as u64,
                allocated_bytes: allocated as u64,
            }));
        }
        if next == 0 {
            return Ok(None);
        }
        if next < STREAM_LAYOUT_HEADER_BYTES + identifier_bytes {
            return Err("layout_stream_chain_overlaps");
        }
        offset = offset
            .checked_add(next)
            .filter(|offset| *offset < record_end)
            .ok_or("layout_stream_chain_out_of_bounds")?;
    }
    Err("layout_stream_chain_limit_exceeded")
}

/// Parses the payload after the leading next-USN cursor returned by `FSCTL_READ_USN_JOURNAL`.
pub fn parse_usn_v2_page(bytes: &[u8]) -> Result<Vec<UsnV2Record>, &'static str> {
    if bytes.len() < size_of::<i64>() {
        return Err("usn_page_cursor_truncated");
    }
    let mut offset = size_of::<i64>();
    let mut records = Vec::new();
    while offset < bytes.len() {
        if records.len() >= MAX_USN_RECORDS {
            return Err("usn_record_limit_exceeded");
        }
        let record_length = read_u32(bytes, offset)? as usize;
        if record_length < USN_V2_FIXED_BYTES || !record_length.is_multiple_of(8) {
            return Err("usn_record_length_invalid");
        }
        let record_end = offset
            .checked_add(record_length)
            .filter(|end| *end <= bytes.len())
            .ok_or("usn_record_truncated")?;
        if read_u16(bytes, offset + 4)? != SUPPORTED_USN_MAJOR_VERSION {
            return Err("usn_record_version_unsupported");
        }
        let name_length = read_u16(bytes, offset + 56)? as usize;
        let name_offset = read_u16(bytes, offset + 58)? as usize;
        if !name_length.is_multiple_of(2) || name_offset < USN_V2_FIXED_BYTES {
            return Err("usn_name_range_invalid");
        }
        let name_start = offset
            .checked_add(name_offset)
            .ok_or("usn_name_range_invalid")?;
        let name_end = name_start
            .checked_add(name_length)
            .filter(|end| *end <= record_end)
            .ok_or("usn_name_range_invalid")?;
        let (name_units, remainder) = bytes[name_start..name_end].as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        let name = name_units
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect::<Vec<_>>();
        if name.contains(&0) {
            return Err("usn_name_contains_nul");
        }
        records.push(UsnV2Record {
            file_reference_number: read_u64(bytes, offset + 8)?,
            parent_file_reference_number: read_u64(bytes, offset + 16)?,
            usn: read_i64(bytes, offset + 24)?,
            reason: read_u32(bytes, offset + 40)?,
            file_attributes: read_u32(bytes, offset + 52)?,
            name,
        });
        offset = record_end;
    }
    Ok(records)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or("integer_out_of_bounds")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or("integer_out_of_bounds")?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("checked u32 range"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, &'static str> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or("integer_out_of_bounds")?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("checked u64 range"),
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, &'static str> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or("integer_out_of_bounds")?;
    Ok(i64::from_le_bytes(
        value.try_into().expect("checked i64 range"),
    ))
}

#[cfg(windows)]
pub(crate) mod native {
    use std::ffi::{OsString, c_void};
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_HANDLE_EOF, GENERIC_READ, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetVolumeInformationW,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        FSCTL_QUERY_FILE_LAYOUT, FSCTL_QUERY_USN_JOURNAL, QUERY_FILE_LAYOUT_FILTER_TYPE_NONE,
        QUERY_FILE_LAYOUT_INCLUDE_NAMES, QUERY_FILE_LAYOUT_INCLUDE_STREAMS,
        QUERY_FILE_LAYOUT_INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED, QUERY_FILE_LAYOUT_INPUT,
        QUERY_FILE_LAYOUT_RESTART, USN_JOURNAL_DATA_V0,
    };

    use super::*;

    struct OwnedVolume(HANDLE);

    impl OwnedVolume {
        fn open(root: &Path) -> Result<Self, NtfsAccelerationFallback> {
            let Some((device, volume_root)) = volume_paths(root) else {
                return Err(NtfsAccelerationFallback::UnsupportedRoot);
            };
            if !is_ntfs(&volume_root) {
                return Err(NtfsAccelerationFallback::UnsupportedFilesystem);
            }
            let wide = device.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let handle = unsafe {
                // SAFETY: the UTF-16 path is terminated and all pointer arguments remain valid for
                // this synchronous open. The returned handle is closed exactly once by Drop.
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    ptr::null(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(NtfsAccelerationFallback::AccessDeniedOrUnavailable);
            }
            Ok(Self(handle))
        }
    }

    impl Drop for OwnedVolume {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: OwnedVolume is the sole owner of a successful CreateFileW handle.
                CloseHandle(self.0);
            }
        }
    }

    fn volume_paths(path: &Path) -> Option<(String, PathBuf)> {
        let mut components = path.components();
        let Component::Prefix(prefix) = components.next()? else {
            return None;
        };
        let drive = match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return None,
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return None;
        }
        let letter = char::from(drive).to_ascii_uppercase();
        Some((
            format!(r"\\.\{letter}:"),
            PathBuf::from(format!(r"{letter}:\")),
        ))
    }

    fn is_ntfs(volume_root: &Path) -> bool {
        let root = volume_root
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut filesystem = [0u16; 64];
        let success = unsafe {
            // SAFETY: both UTF-16 buffers are valid and the output length matches the allocation.
            GetVolumeInformationW(
                root.as_ptr(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        };
        let Some(length) = filesystem.iter().position(|unit| *unit == 0) else {
            return false;
        };
        success != 0
            && OsString::from_wide(&filesystem[..length])
                .to_string_lossy()
                .eq_ignore_ascii_case("ntfs")
    }

    /// Result of probing the current USN journal through an already-open volume handle.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NativeUsnProbe {
        Available(UsnJournalBounds),
        Unavailable(u32),
    }

    /// Reads current journal bounds. Unsupported or denied access is explicit and must be treated
    /// as a cache miss by the caller; this function never creates or mutates a journal.
    pub fn query_usn_journal(volume: HANDLE) -> NativeUsnProbe {
        let mut output = USN_JOURNAL_DATA_V0::default();
        let mut returned = 0u32;
        let success = unsafe {
            // SAFETY: `volume` is borrowed for this synchronous call, no input buffer is required,
            // and the initialized fixed-size output remains writable for its full declared length.
            DeviceIoControl(
                volume,
                FSCTL_QUERY_USN_JOURNAL,
                ptr::null(),
                0,
                ptr::from_mut(&mut output).cast::<c_void>(),
                size_of::<USN_JOURNAL_DATA_V0>() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if success == 0 || returned < size_of::<USN_JOURNAL_DATA_V0>() as u32 {
            return NativeUsnProbe::Unavailable(unsafe { GetLastError() });
        }
        NativeUsnProbe::Available(UsnJournalBounds {
            journal_id: output.UsnJournalID,
            first_usn: output.FirstUsn,
            next_usn: output.NextUsn,
            lowest_valid_usn: output.LowestValidUsn,
        })
    }

    /// Reads and validates bounded NTFS layout pages from an already-open volume handle.
    ///
    /// Any native or parser failure returns an error so callers can discard partial layout data and
    /// restart with the existing handle-relative traversal.
    pub fn query_file_layout(volume: HANDLE, cancelled: impl Fn() -> bool) -> Result<u64, u32> {
        let mut input = QUERY_FILE_LAYOUT_INPUT::default();
        input.Anonymous.FilterEntryCount = 0;
        input.Flags = QUERY_FILE_LAYOUT_RESTART
            | QUERY_FILE_LAYOUT_INCLUDE_NAMES
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED;
        input.FilterType = QUERY_FILE_LAYOUT_FILTER_TYPE_NONE;
        let mut buffer = vec![0u64; FILE_LAYOUT_PAGE_BYTES.div_ceil(size_of::<u64>())];
        let mut record_count = 0u64;
        for _ in 0..MAX_NATIVE_PAGES {
            if cancelled() {
                return Err(995); // ERROR_OPERATION_ABORTED
            }
            let mut returned = 0u32;
            let success = unsafe {
                // SAFETY: the volume and all buffers remain live for this synchronous call. The
                // output uses aligned u64 storage and only the returned prefix is parsed.
                DeviceIoControl(
                    volume,
                    FSCTL_QUERY_FILE_LAYOUT,
                    ptr::from_ref(&input).cast::<c_void>(),
                    size_of::<QUERY_FILE_LAYOUT_INPUT>() as u32,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    FILE_LAYOUT_PAGE_BYTES as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            if success == 0 {
                let code = unsafe { GetLastError() };
                if code == ERROR_HANDLE_EOF {
                    return Ok(record_count);
                }
                return Err(code);
            }
            if returned == 0 || returned as usize > FILE_LAYOUT_PAGE_BYTES {
                return Err(13); // ERROR_INVALID_DATA
            }
            let bytes = unsafe {
                // SAFETY: `returned` was checked against the initialized allocation capacity.
                std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize)
            };
            let page = parse_file_layout_page(bytes).map_err(|_| 13u32)?;
            record_count = record_count.checked_add(page.len() as u64).ok_or(234u32)?;
            if record_count > MAX_FILE_LAYOUT_RECORDS {
                return Err(234); // ERROR_MORE_DATA: caller must fall back, not truncate.
            }
            input.Flags &= !QUERY_FILE_LAYOUT_RESTART;
        }
        Err(234)
    }

    /// Raw per-FSCTL outcome on a real volume, for qualification tests only.
    ///
    /// `probe` deliberately collapses every native error into one fallback variant, because
    /// callers only need "acceleration is unusable, traverse instead". Qualification needs the
    /// opposite: `ERROR_INVALID_FUNCTION (1)`, `ERROR_ACCESS_DENIED (5)` and
    /// `ERROR_INVALID_PARAMETER (87)` demand completely different responses — the first means
    /// the control code does not exist at this handle level, the second means privilege, and
    /// the third means *our own input struct is wrong*. Collapsing them is right for
    /// production and useless for deciding whether an accelerator is worth building, so this
    /// seam exists to keep that judgement grounded in observed codes rather than inference.
    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NativeFsctlOutcome {
        /// `None` when the volume handle itself could not be opened.
        pub open_error: Option<u32>,
        /// `Ok` carries journal bounds; `Err` carries the raw Win32 code.
        pub usn: Option<Result<UsnJournalBounds, u32>>,
        /// `Ok` carries the record count; `Err` carries the raw Win32 code.
        pub layout: Option<Result<u64, u32>>,
        /// First-page diagnosis: `Ok` is the parsed record count, `Err` names the failing
        /// structural check. `query_file_layout` maps every parser error to `13`, which cannot
        /// distinguish "the kernel returned a short buffer" from "our layout parser is wrong".
        pub layout_parse: Option<Result<usize, &'static str>>,
        /// Bytes the kernel returned for the first page, and its leading header words.
        pub layout_page: Option<(u32, u32, u32)>,
    }

    /// Runs both FSCTLs against `root` and reports raw codes without collapsing them.
    #[cfg(test)]
    pub fn measure_fsctl_outcomes(root: &Path, cancel: &CancellationToken) -> NativeFsctlOutcome {
        let volume = match OwnedVolume::open(root) {
            Ok(volume) => volume,
            Err(_) => {
                return NativeFsctlOutcome {
                    open_error: Some(unsafe { GetLastError() }),
                    usn: None,
                    layout: None,
                    layout_parse: None,
                    layout_page: None,
                };
            }
        };
        let usn = match query_usn_journal(volume.0) {
            NativeUsnProbe::Available(bounds) => Ok(bounds),
            NativeUsnProbe::Unavailable(code) => Err(code),
        };
        // The layout query runs regardless of the USN result: they are independent control
        // codes and one failing must not hide the other's status.
        let layout = query_file_layout(volume.0, || cancel.is_cancelled());

        // Re-issue only the first page to see what the kernel actually returns, so a parser
        // rejection can be told apart from a native refusal.
        let mut input = QUERY_FILE_LAYOUT_INPUT::default();
        input.Anonymous.FilterEntryCount = 0;
        input.Flags = QUERY_FILE_LAYOUT_RESTART
            | QUERY_FILE_LAYOUT_INCLUDE_NAMES
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED;
        input.FilterType = QUERY_FILE_LAYOUT_FILTER_TYPE_NONE;
        let mut buffer = vec![0u64; FILE_LAYOUT_PAGE_BYTES.div_ceil(size_of::<u64>())];
        let mut returned = 0u32;
        let ok = unsafe {
            // SAFETY: identical contract to `query_file_layout`; buffers outlive the call.
            DeviceIoControl(
                volume.0,
                FSCTL_QUERY_FILE_LAYOUT,
                ptr::from_ref(&input).cast::<c_void>(),
                size_of::<QUERY_FILE_LAYOUT_INPUT>() as u32,
                buffer.as_mut_ptr().cast::<c_void>(),
                FILE_LAYOUT_PAGE_BYTES as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        let (layout_parse, layout_page) = if ok == 0 {
            (Some(Err("native_call_failed")), None)
        } else {
            let bytes = unsafe {
                // SAFETY: only the prefix the kernel reported as written is read.
                std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize)
            };
            let header = (
                returned,
                read_u32(bytes, 0).unwrap_or(u32::MAX),
                read_u32(bytes, 4).unwrap_or(u32::MAX),
            );
            (
                Some(parse_file_layout_page(bytes).map(|page| page.len())),
                Some(header),
            )
        };

        NativeFsctlOutcome {
            open_error: None,
            usn: Some(usn),
            layout: Some(layout),
            layout_parse,
            layout_page,
        }
    }

    /// Reads one layout page and returns the parsed records, for qualification tests only.
    #[cfg(test)]
    pub fn read_first_layout_page(root: &Path) -> Result<Vec<FileLayoutRecord>, u32> {
        let volume = OwnedVolume::open(root).map_err(|_| unsafe { GetLastError() })?;
        let mut input = QUERY_FILE_LAYOUT_INPUT::default();
        input.Anonymous.FilterEntryCount = 0;
        input.Flags = QUERY_FILE_LAYOUT_RESTART
            | QUERY_FILE_LAYOUT_INCLUDE_NAMES
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED;
        input.FilterType = QUERY_FILE_LAYOUT_FILTER_TYPE_NONE;
        let mut buffer = vec![0u64; FILE_LAYOUT_PAGE_BYTES.div_ceil(size_of::<u64>())];
        let mut returned = 0u32;
        let ok = unsafe {
            // SAFETY: same contract as `query_file_layout`; buffers outlive the call.
            DeviceIoControl(
                volume.0,
                FSCTL_QUERY_FILE_LAYOUT,
                ptr::from_ref(&input).cast::<c_void>(),
                size_of::<QUERY_FILE_LAYOUT_INPUT>() as u32,
                buffer.as_mut_ptr().cast::<c_void>(),
                FILE_LAYOUT_PAGE_BYTES as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        let bytes = unsafe {
            // SAFETY: only the prefix the kernel reported as written is read.
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize)
        };
        parse_file_layout_page(bytes).map_err(|_| u32::MAX)
    }

    /// Reads every layout page and returns all parsed records.
    ///
    /// Mirrors `query_file_layout`'s paging exactly, including the bound: exceeding
    /// `MAX_FILE_LAYOUT_RECORDS` is an error rather than a truncated set, because a caller that
    /// silently received "most of the volume" would compute totals that look exact and are not.
    ///
    /// Requires elevation, like every `FSCTL_QUERY_FILE_LAYOUT` caller; unelevated hosts get a
    /// Win32 error and must fall back to the portable traversal.
    pub fn read_all_layout_records(
        root: &Path,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<FileLayoutRecord>, u32> {
        let volume = OwnedVolume::open(root).map_err(|_| unsafe { GetLastError() })?;
        let mut input = QUERY_FILE_LAYOUT_INPUT::default();
        input.Anonymous.FilterEntryCount = 0;
        input.Flags = QUERY_FILE_LAYOUT_RESTART
            | QUERY_FILE_LAYOUT_INCLUDE_NAMES
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS
            | QUERY_FILE_LAYOUT_INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED;
        input.FilterType = QUERY_FILE_LAYOUT_FILTER_TYPE_NONE;
        let mut buffer = vec![0u64; FILE_LAYOUT_PAGE_BYTES.div_ceil(size_of::<u64>())];
        let mut all = Vec::new();
        for _ in 0..MAX_NATIVE_PAGES {
            if cancelled() {
                return Err(995);
            }
            let mut returned = 0u32;
            let success = unsafe {
                // SAFETY: identical contract to `query_file_layout`.
                DeviceIoControl(
                    volume.0,
                    FSCTL_QUERY_FILE_LAYOUT,
                    ptr::from_ref(&input).cast::<c_void>(),
                    size_of::<QUERY_FILE_LAYOUT_INPUT>() as u32,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    FILE_LAYOUT_PAGE_BYTES as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            if success == 0 {
                let code = unsafe { GetLastError() };
                if code == ERROR_HANDLE_EOF {
                    return Ok(all);
                }
                return Err(code);
            }
            if returned == 0 || returned as usize > FILE_LAYOUT_PAGE_BYTES {
                return Err(13);
            }
            let bytes = unsafe {
                // SAFETY: `returned` was bounds-checked against the allocation.
                std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize)
            };
            all.extend(parse_file_layout_page(bytes).map_err(|_| 13u32)?);
            if all.len() as u64 > MAX_FILE_LAYOUT_RECORDS {
                return Err(234);
            }
            input.Flags &= !QUERY_FILE_LAYOUT_RESTART;
        }
        Err(234)
    }

    pub fn probe(root: &Path, cancel: &CancellationToken) -> NtfsAccelerationProbe {
        if cancel.is_cancelled() {
            return NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::Cancelled);
        }
        let volume = match OwnedVolume::open(root) {
            Ok(volume) => volume,
            Err(reason) => return NtfsAccelerationProbe::Fallback(reason),
        };
        let journal = match query_usn_journal(volume.0) {
            NativeUsnProbe::Available(bounds) => bounds,
            NativeUsnProbe::Unavailable(ERROR_ACCESS_DENIED) => {
                return NtfsAccelerationProbe::Fallback(
                    NtfsAccelerationFallback::AccessDeniedOrUnavailable,
                );
            }
            NativeUsnProbe::Unavailable(_) => {
                return NtfsAccelerationProbe::Fallback(
                    NtfsAccelerationFallback::InvalidNativeData,
                );
            }
        };
        match query_file_layout(volume.0, || cancel.is_cancelled()) {
            Ok(layout_records) => NtfsAccelerationProbe::Available {
                layout_records,
                journal,
            },
            Err(995) => NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::Cancelled),
            Err(234) => NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::ResourceLimit),
            Err(ERROR_ACCESS_DENIED) => {
                NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::AccessDeniedOrUnavailable)
            }
            Err(_) => NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::InvalidNativeData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_page_rejects_offsets_outside_the_record() {
        let mut bytes = vec![0; 80];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&16u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&128u32.to_le_bytes());
        assert_eq!(
            parse_file_layout_page(&bytes),
            Err("layout_child_offset_out_of_bounds")
        );
    }

    #[test]
    fn usn_page_parses_one_version_two_record() {
        let mut bytes = vec![0; 8 + 64];
        bytes[8..12].copy_from_slice(&64u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&2u16.to_le_bytes());
        bytes[16..24].copy_from_slice(&42u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&7u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&99i64.to_le_bytes());
        bytes[48..52].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[60..64].copy_from_slice(&0x20u32.to_le_bytes());
        bytes[64..66].copy_from_slice(&4u16.to_le_bytes());
        bytes[66..68].copy_from_slice(&60u16.to_le_bytes());
        bytes[68..72].copy_from_slice(&[b'a', 0, b'b', 0]);
        let parsed = parse_usn_v2_page(&bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].file_reference_number, 42);
        assert_eq!(parsed[0].name, [b'a' as u16, b'b' as u16]);
    }

    #[test]
    fn layout_page_parses_one_bounded_record() {
        let mut bytes = vec![0; 80];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&16u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0x20u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&42u64.to_le_bytes());
        let records = parse_file_layout_page(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].file_reference_number, 42);
        assert_eq!(records[0].length, 64);
    }

    #[test]
    fn layout_page_parses_name_and_default_data_stream() {
        let mut bytes = vec![0; 160];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&16u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&42u64.to_le_bytes());
        bytes[40..44].copy_from_slice(&48u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&88u32.to_le_bytes());
        let name = 64usize;
        bytes[name + 8..name + 16].copy_from_slice(&7u64.to_le_bytes());
        bytes[name + 16..name + 20].copy_from_slice(&4u32.to_le_bytes());
        bytes[name + 24..name + 28].copy_from_slice(&[b'a', 0, b'b', 0]);
        let stream = 104usize;
        bytes[stream..stream + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[stream + 16..stream + 24].copy_from_slice(&8192i64.to_le_bytes());
        bytes[stream + 24..stream + 32].copy_from_slice(&4096i64.to_le_bytes());
        bytes[stream + 36..stream + 40].copy_from_slice(&NTFS_DATA_ATTRIBUTE.to_le_bytes());

        let records = parse_file_layout_page(&bytes).unwrap();
        assert_eq!(records[0].names[0].name, [b'a' as u16, b'b' as u16]);
        assert_eq!(records[0].names[0].parent_file_reference_number, 7);
        assert_eq!(
            records[0].default_data_stream,
            Some(FileLayoutDataStream {
                logical_bytes: 4096,
                allocated_bytes: 8192,
            })
        );
    }

    #[test]
    fn usn_page_rejects_unknown_versions_and_invalid_name_ranges() {
        let mut bytes = vec![0; 8 + 64];
        bytes[8..12].copy_from_slice(&64u32.to_le_bytes());
        bytes[12..14].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            parse_usn_v2_page(&bytes),
            Err("usn_record_version_unsupported")
        );

        bytes[12..14].copy_from_slice(&2u16.to_le_bytes());
        bytes[64..66].copy_from_slice(&3u16.to_le_bytes());
        bytes[66..68].copy_from_slice(&60u16.to_le_bytes());
        assert_eq!(parse_usn_v2_page(&bytes), Err("usn_name_range_invalid"));
    }

    #[test]
    fn usn_cursor_never_reuses_changed_wrapped_or_future_history() {
        let bounds = UsnJournalBounds {
            journal_id: 7,
            first_usn: 100,
            next_usn: 200,
            lowest_valid_usn: 110,
        };
        assert_eq!(
            validate_usn_cursor(7, 150, bounds),
            UsnCursorDecision::ReadFrom(150)
        );
        assert_eq!(
            validate_usn_cursor(8, 150, bounds),
            UsnCursorDecision::CacheMiss(UsnCacheMissReason::JournalChanged)
        );
        assert_eq!(
            validate_usn_cursor(7, 109, bounds),
            UsnCursorDecision::CacheMiss(UsnCacheMissReason::JournalWrapped)
        );
        assert_eq!(
            validate_usn_cursor(7, 201, bounds),
            UsnCursorDecision::CacheMiss(UsnCacheMissReason::CursorAhead)
        );
    }

    /// Builds a one-record layout page whose single name is `name_units`.
    #[cfg(test)]
    fn layout_page_with_name(name_units: &[u16]) -> Vec<u8> {
        let name_bytes = name_units.len() * 2;
        let mut bytes = vec![0u8; 64 + 24 + name_bytes.max(8) + 8];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&16u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&42u64.to_le_bytes());
        bytes[40..44].copy_from_slice(&48u32.to_le_bytes());
        let name = 64usize;
        bytes[name + 8..name + 16].copy_from_slice(&7u64.to_le_bytes());
        bytes[name + 16..name + 20].copy_from_slice(&(name_bytes as u32).to_le_bytes());
        for (index, unit) in name_units.iter().enumerate() {
            let at = name + 24 + index * 2;
            bytes[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    /// The NTFS root record is named `.` and must not invalidate the page containing it.
    ///
    /// Regression test for a measured failure: an elevated `FSCTL_QUERY_FILE_LAYOUT` returned
    /// 17409 valid records, and rejecting the single root record discarded all of them, so the
    /// accelerator appeared unsupported on every NTFS volume. The name is accepted but not
    /// exposed as a composable component, since joining `.` into a path would name the wrong
    /// directory.
    #[test]
    fn the_ntfs_root_dot_name_is_accepted_without_becoming_a_path_component() {
        let records = parse_file_layout_page(&layout_page_with_name(&[b'.' as u16]))
            .expect("a page containing the root record must parse");
        assert_eq!(records.len(), 1, "the record itself is still reported");
        assert!(
            records[0].names.is_empty(),
            "`.` must not be offered as a name that could be joined into a path"
        );
    }

    /// `..` is never a real NTFS filename, so it must keep failing closed.
    ///
    /// Guards the other half of the same check: relaxing `.` must not also admit a parent
    /// reference, which could otherwise escape a reconstructed directory.
    #[test]
    fn a_parent_reference_name_still_invalidates_the_page() {
        assert_eq!(
            parse_file_layout_page(&layout_page_with_name(&[b'.' as u16, b'.' as u16])),
            Err("layout_name_invalid"),
            "`..` must never be accepted from a layout page"
        );
    }

    /// Ordinary names are unaffected by the root-record allowance.
    #[test]
    fn an_ordinary_name_is_still_returned_as_a_component() {
        let records = parse_file_layout_page(&layout_page_with_name(&[b'a' as u16, b'b' as u16]))
            .expect("an ordinary name parses");
        assert_eq!(records[0].names.len(), 1);
        assert_eq!(records[0].names[0].name, [b'a' as u16, b'b' as u16]);
    }

    /// Compares the accelerated source against an independent directory walk of the same tree.
    ///
    /// Set `SWEEPX_RUN_NATIVE_NTFS_PROBE=1` and run elevated. The oracle is `std::fs`, which
    /// reaches the filesystem through a completely different path than
    /// `FSCTL_QUERY_FILE_LAYOUT`, so agreement is real evidence rather than one reader agreeing
    /// with itself. Both the file set and the summed byte count must match: matching names with
    /// wrong sizes would still produce wrong totals for the user.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires an elevated run on a real NTFS volume"]
    fn the_accelerated_source_agrees_with_a_directory_walk() {
        if std::env::var_os("SWEEPX_RUN_NATIVE_NTFS_PROBE").as_deref() != Some("1".as_ref()) {
            return;
        }
        use crate::select_subtree;
        use std::collections::BTreeMap;
        use std::ffi::c_void;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::ptr;
        use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx,
            OPEN_EXISTING,
        };

        let subject = std::path::Path::new(
            &std::env::var("SWEEPX_PROBE_SUBTREE")
                .unwrap_or_else(|_| r"E:\Projects\sweepx\crates".to_string()),
        )
        .to_path_buf();
        let subject = subject.as_path();
        if !subject.exists() {
            println!("SKIP: subject tree missing");
            return;
        }

        // The scan root's own reference number, read from a live open. Membership is decided
        // against this rather than against any name, so the subtree cannot be widened by a
        // crafted or corrupt name string.
        let wide: Vec<u16> = subject.as_os_str().encode_wide().chain(Some(0)).collect();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        assert!(
            raw != INVALID_HANDLE_VALUE && !raw.is_null(),
            "open subject"
        );
        // SAFETY: validated handle, closed on drop.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as _) };
        let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.as_raw_handle() as HANDLE,
                FileIdInfo,
                ptr::from_mut(&mut info).cast::<c_void>(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        assert_ne!(ok, 0, "read subject identity");
        let root_reference = u64::from_le_bytes(info.FileId.Identifier[0..8].try_into().unwrap());

        let accelerated_started = std::time::Instant::now();
        let snapshot_taken_at = std::time::SystemTime::now();
        let records = native::read_all_layout_records(std::path::Path::new("E:\\"), &|| false)
            .expect("elevated layout read");
        let subtree = select_subtree(&records, root_reference, subject);
        let accelerated_elapsed = accelerated_started.elapsed();

        // Independent oracle: an ordinary recursive directory walk.
        let walk_started = std::time::Instant::now();
        let mut oracle = BTreeMap::<std::path::PathBuf, Option<u64>>::new();
        let mut stack = vec![subject.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else { continue };
                if meta.file_type().is_symlink() {
                    continue;
                }
                let path = entry.path();
                if meta.is_dir() {
                    oracle.insert(path.clone(), None);
                    stack.push(path);
                } else {
                    oracle.insert(path, Some(meta.len()));
                }
            }
        }
        let walk_elapsed = walk_started.elapsed();

        let accelerated: BTreeMap<std::path::PathBuf, Option<u64>> = subtree
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.path.clone(),
                    if entry.is_directory {
                        None
                    } else {
                        entry.logical_bytes
                    },
                )
            })
            .collect();

        let missing: Vec<_> = oracle
            .keys()
            .filter(|path| !accelerated.contains_key(*path))
            .take(40)
            .cloned()
            .collect();
        let extra: Vec<_> = accelerated
            .keys()
            .filter(|path| !oracle.contains_key(*path))
            .take(40)
            .cloned()
            .collect();

        let oracle_bytes: u64 = oracle.values().flatten().sum();
        let accelerated_bytes: u64 = accelerated.values().flatten().sum();

        println!(
            "accelerated={} oracle={} accel_time={:.3}s walk_time={:.3}s skipped={}",
            accelerated.len(),
            oracle.len(),
            accelerated_elapsed.as_secs_f64(),
            walk_elapsed.as_secs_f64(),
            subtree.skipped.len()
        );
        println!("bytes accelerated={accelerated_bytes} oracle={oracle_bytes}");

        // Diagnose a mismatch rather than only reporting its size: a path created after the
        // snapshot is a live-tree race, while an older path is a real defect in selection.
        if !missing.is_empty() || !extra.is_empty() {
            for path in &missing {
                let created_after = std::fs::metadata(path)
                    .and_then(|meta| meta.modified())
                    .map(|modified| modified > snapshot_taken_at)
                    .unwrap_or(false);
                println!(
                    "MISSING newer_than_snapshot={created_after} {}",
                    path.display()
                );
            }
            for path in &extra {
                println!("EXTRA exists={} {}", path.exists(), path.display());
            }
        }

        assert!(
            missing.is_empty(),
            "the accelerated source missed {} path(s), e.g. {missing:?}",
            oracle.len().saturating_sub(accelerated.len())
        );
        assert!(
            extra.is_empty(),
            "the accelerated source invented {extra:?}"
        );
        assert_eq!(
            accelerated_bytes, oracle_bytes,
            "summed file bytes must match the directory walk exactly"
        );
    }

    /// Compares reconstructed paths against the paths the OS reports for the same records.
    ///
    /// Set `SWEEPX_RUN_NATIVE_NTFS_PROBE=1` and run elevated. Synthetic reconstruction tests can
    /// only prove the walk is self-consistent with our *model* of the MFT; this is the test that
    /// can show the model is wrong about the real filesystem. Each record is resolved by
    /// reference number through the unprivileged verification path, its path read back with
    /// `GetFinalPathNameByHandleW`, and compared against the reconstruction.
    ///
    /// A mismatch is a hard failure. A record we refuse to reconstruct is not: refusals are the
    /// designed outcome for partial pages and inconsistent chains, so they are counted and
    /// reported rather than asserted away.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires an elevated run on a real NTFS volume"]
    fn reconstructed_paths_match_the_paths_the_os_reports() {
        if std::env::var_os("SWEEPX_RUN_NATIVE_NTFS_PROBE").as_deref() != Some("1".as_ref()) {
            return;
        }
        use crate::{AcceleratedClaim, RecordIndex, verify_accelerated_record};
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use std::ptr;
        use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_DESCRIPTOR, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW, OPEN_EXISTING,
            OpenFileById, VOLUME_NAME_DOS,
        };

        for root in ["E:\\", "C:\\"] {
            let path = std::path::Path::new(root);
            if !path.exists() {
                println!("SKIP {root}");
                continue;
            }
            let records = match native::read_first_layout_page(path) {
                Ok(records) => records,
                Err(code) => panic!("{root}: reading a layout page failed with {code}"),
            };
            let index = RecordIndex::from_records(&records);
            println!("{root}: {} records indexed", index.len());

            // Report the actual name flag values observed, so name preference is based on
            // measurement rather than on an assumed bit layout.
            let mut flag_histogram: std::collections::BTreeMap<u32, usize> =
                std::collections::BTreeMap::new();
            let mut multi_name_examples = 0;
            for record in &records {
                for name in &record.names {
                    *flag_histogram.entry(name.flags).or_default() += 1;
                }
                if record.names.len() > 1 && multi_name_examples < 5 {
                    multi_name_examples += 1;
                    let rendered: Vec<String> = record
                        .names
                        .iter()
                        .map(|name| {
                            format!(
                                "flags=0x{:x} '{}'",
                                name.flags,
                                String::from_utf16_lossy(&name.name)
                            )
                        })
                        .collect();
                    println!("  multi-name record: {}", rendered.join(" | "));
                }
            }
            println!("  name flag histogram: {flag_histogram:?}");

            // An ordinary handle on the volume, which is all the verification path needs.
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    ptr::null_mut(),
                )
            };
            assert!(
                raw != INVALID_HANDLE_VALUE && !raw.is_null(),
                "{root}: hint"
            );
            // SAFETY: validated handle, ownership transferred once.
            let hint = unsafe { OwnedHandle::from_raw_handle(raw as _) };

            let (mut compared, mut agreed, mut refused, mut unresolvable) = (0, 0, 0, 0);
            let mut mismatches = Vec::new();

            for record in records.iter().take(4000) {
                let components = match index.reconstruct_components(record.file_reference_number) {
                    Ok(components) => components,
                    Err(_) => {
                        refused += 1;
                        continue;
                    }
                };
                let is_directory = record.file_attributes & 0x10 != 0;
                let verified = match verify_accelerated_record(
                    &hint,
                    AcceleratedClaim {
                        file_reference_number: record.file_reference_number,
                        is_directory,
                    },
                ) {
                    Ok(verified) => verified,
                    Err(_) => {
                        // Metadata files and records that vanished mid-run are expected here.
                        unresolvable += 1;
                        continue;
                    }
                };
                let _ = verified;

                // Reopen to ask the OS for its own answer.
                let mut descriptor: FILE_ID_DESCRIPTOR = unsafe { std::mem::zeroed() };
                descriptor.dwSize = size_of::<FILE_ID_DESCRIPTOR>() as u32;
                descriptor.Type = 0;
                descriptor.Anonymous.FileId = record.file_reference_number as i64;
                let opened = unsafe {
                    OpenFileById(
                        hint.as_raw_handle() as HANDLE,
                        &descriptor,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        ptr::null(),
                        FILE_FLAG_BACKUP_SEMANTICS,
                    )
                };
                if opened == INVALID_HANDLE_VALUE || opened.is_null() {
                    unresolvable += 1;
                    continue;
                }
                // SAFETY: validated handle, closed on drop.
                let opened = unsafe { OwnedHandle::from_raw_handle(opened as _) };
                let mut name_buffer = vec![0u16; 32768];
                let written = unsafe {
                    GetFinalPathNameByHandleW(
                        opened.as_raw_handle() as HANDLE,
                        name_buffer.as_mut_ptr(),
                        name_buffer.len() as u32,
                        VOLUME_NAME_DOS,
                    )
                };
                if written == 0 || written as usize >= name_buffer.len() {
                    unresolvable += 1;
                    continue;
                }
                let reported = String::from_utf16_lossy(&name_buffer[..written as usize]);
                let reported = reported.trim_start_matches(r"\\?\").replace('/', "\\");
                let rebuilt = components
                    .iter()
                    .map(|part| String::from_utf16_lossy(part))
                    .collect::<Vec<_>>()
                    .join("\\");
                let expected = format!("{}{}", root, rebuilt);

                compared += 1;
                if reported.eq_ignore_ascii_case(&expected) {
                    agreed += 1;
                } else if mismatches.len() < 10 {
                    mismatches.push(format!("  rebuilt={expected}\n  reported={reported}"));
                }
            }

            println!(
                "{root}: compared={compared} agreed={agreed} refused={refused} unresolvable={unresolvable}"
            );
            assert!(
                compared > 0,
                "{root}: no record could be compared, so this proves nothing"
            );
            assert!(
                mismatches.is_empty(),
                "{root}: {} reconstructed path(s) disagree with the OS:\n{}",
                mismatches.len(),
                mismatches.join("\n")
            );
        }
    }

    /// Qualifies the shipped FSCTL call forms against a real NTFS volume.
    ///
    /// Set `SWEEPX_RUN_NATIVE_NTFS_PROBE=1` and run elevated. This is the test that decides
    /// whether the accelerator is worth building, so it asserts on raw codes rather than on
    /// the collapsed fallback: `native_ntfs_probe_is_bounded_and_read_only` only requires an
    /// elevated run to avoid `NotElevated`, which a permanently broken `FSCTL_QUERY_FILE_LAYOUT`
    /// would still satisfy by falling back to `InvalidNativeData`.
    ///
    /// The decisive assertion is that neither FSCTL may return `ERROR_INVALID_PARAMETER (87)`.
    /// An earlier throwaway probe hit 87 and it was nearly recorded as a platform limitation;
    /// it was actually a malformed input struct in the probe (a missing
    /// `QUERY_FILE_LAYOUT_RESTART` and an impossible cluster filter range). 87 means our own
    /// arguments are wrong, and unlike code 1 or 5 it is always our bug to fix — treating it
    /// as "unsupported" would silently discard a usable accelerator.
    #[cfg(windows)]
    #[test]
    #[ignore = "requires an elevated run on a real NTFS volume"]
    fn shipped_fsctl_call_forms_are_accepted_when_elevated() {
        if std::env::var_os("SWEEPX_RUN_NATIVE_NTFS_PROBE").as_deref() != Some("1".as_ref()) {
            return;
        }
        use sweepx_platform::PrivilegeProvider as _;
        let elevated = crate::WindowsPrivilegeProvider::new()
            .observe()
            .level
            .grants_elevated_capability();

        for root in ["C:\\", "E:\\"] {
            let path = std::path::Path::new(root);
            if !path.exists() {
                println!("SKIP {root}: not present on this host");
                continue;
            }
            let started = std::time::Instant::now();
            let observed = native::measure_fsctl_outcomes(path, &CancellationToken::new());
            let elapsed = started.elapsed();
            println!("{root} elevated={elevated} observed={observed:?}");
            // Timing is reported, never asserted on: a threshold here would fail on slower
            // or busier hosts and say nothing about correctness.
            println!(
                "  {root} native_enumeration_seconds={:.2} (two FSCTL passes)",
                elapsed.as_secs_f64()
            );

            if !elevated {
                // Documents the measured floor: the volume handle needs GENERIC_READ, which
                // an unelevated process cannot obtain, so there is nothing further to assert.
                assert!(
                    observed.open_error.is_some(),
                    "an unelevated process must not obtain a GENERIC_READ volume handle"
                );
                continue;
            }

            assert!(
                observed.open_error.is_none(),
                "{root}: an elevated process must open the volume, got error {:?}",
                observed.open_error
            );

            let usn = observed.usn.expect("elevated run reaches the USN query");
            assert_ne!(
                usn.err(),
                Some(87),
                "{root}: FSCTL_QUERY_USN_JOURNAL rejected our input struct (87); \
                 that is a bug in the call form, not a platform limit"
            );
            assert!(
                usn.is_ok(),
                "{root}: FSCTL_QUERY_USN_JOURNAL must succeed when elevated, got {usn:?}"
            );

            let layout = observed
                .layout
                .expect("elevated run reaches the layout query");
            println!(
                "  {root} layout={layout:?} parse={:?} page={:?}",
                observed.layout_parse, observed.layout_page
            );
            assert_ne!(
                layout.err(),
                Some(87),
                "{root}: FSCTL_QUERY_FILE_LAYOUT rejected our input struct (87); \
                 the shipped call form must be corrected rather than recorded as unsupported"
            );
            // A parser rejection is our bug, never a platform limit, and must not be allowed
            // to masquerade as "acceleration unsupported here".
            assert!(
                observed.layout_parse.is_none_or(|parsed| parsed.is_ok()),
                "{root}: the layout page the kernel returned must parse, got {:?}",
                observed.layout_parse
            );
            // 234 is this crate's own bound, not a platform refusal: a volume larger than
            // MAX_FILE_LAYOUT_RECORDS legitimately exhausts the page budget, and that still
            // proves the call form is accepted.
            assert!(
                layout.is_ok() || layout.err() == Some(234),
                "{root}: FSCTL_QUERY_FILE_LAYOUT must be accepted when elevated, got {layout:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an explicit native NTFS CI fixture"]
    fn native_ntfs_probe_is_bounded_and_read_only() {
        if std::env::var_os("SWEEPX_RUN_NATIVE_NTFS_PROBE").as_deref() != Some("1".as_ref()) {
            return;
        }
        let root = std::env::var_os("SystemDrive")
            .map(|drive| std::path::PathBuf::from(format!("{}\\", drive.to_string_lossy())))
            .expect("native Windows CI has SystemDrive");
        let result = probe_ntfs_acceleration(&root, &CancellationToken::new());
        assert!(matches!(
            result,
            NtfsAccelerationProbe::Available { .. }
                | NtfsAccelerationProbe::Fallback(
                    NtfsAccelerationFallback::AccessDeniedOrUnavailable
                        | NtfsAccelerationFallback::InvalidNativeData
                        | NtfsAccelerationFallback::ResourceLimit
                        | NtfsAccelerationFallback::NotElevated
                )
        ));

        // The outcome must agree with the privilege that was actually detected, so a
        // silently broken gate cannot hide behind the permissive allowlist above.
        // Without this, returning `NotElevated` unconditionally would still pass.
        use sweepx_platform::PrivilegeProvider as _;
        let privileged = crate::WindowsPrivilegeProvider::new()
            .observe()
            .level
            .grants_elevated_capability();
        if privileged {
            assert!(
                !matches!(
                    result,
                    NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::NotElevated)
                ),
                "an elevated process must not report NotElevated"
            );
        } else {
            assert!(
                matches!(
                    result,
                    NtfsAccelerationProbe::Fallback(NtfsAccelerationFallback::NotElevated)
                ),
                "an unelevated process cannot open a volume handle, so the probe must \
                 report NotElevated rather than reaching the volume"
            );
        }
    }
}
