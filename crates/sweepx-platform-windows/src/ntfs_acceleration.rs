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
}

/// Probes the native NTFS layout and USN sources without changing filesystem or journal state.
#[cfg(windows)]
pub fn probe_ntfs_acceleration(root: &Path, cancel: &CancellationToken) -> NtfsAccelerationProbe {
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
        if name.is_empty()
            || name.contains(&0)
            || name == [b'.' as u16]
            || name == [b'.' as u16, b'.' as u16]
        {
            return Err("layout_name_invalid");
        }
        names.push(FileLayoutName {
            parent_file_reference_number,
            flags,
            name,
        });
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
mod native {
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
                )
        ));
    }
}
