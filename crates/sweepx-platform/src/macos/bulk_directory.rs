use std::collections::VecDeque;
use std::ffi::CStr;
use std::io;
use std::mem::size_of;
use std::ptr;

use sweepx_model::NativeName;

const ATTR_CMN_ERROR: libc::attrgroup_t = 0x2000_0000;
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;

/// One child decoded from a `getattrlistbulk` page: its native name plus the attributes the
/// scan needs, already shaped as a `stat` so downstream metadata handling is unchanged.
#[derive(Debug)]
pub(super) struct BulkChild {
    pub(super) name: NativeName,
    pub(super) stat: libc::stat,
}

/// Bounded state for Darwin's paged directory-attribute API.
#[derive(Debug)]
pub(super) struct BulkDirectoryCursor {
    buffer: Vec<u64>,
    pending: VecDeque<BulkChild>,
    pages_read: usize,
}

impl BulkDirectoryCursor {
    pub(super) fn new() -> Self {
        Self {
            // u64 storage satisfies the kernel's alignment requirement while the parser exposes
            // only the initialized prefix returned by getattrlistbulk.
            buffer: vec![0; DIRECTORY_BUFFER_BYTES.div_ceil(size_of::<u64>())],
            pending: VecDeque::new(),
            pages_read: 0,
        }
    }

    pub(super) fn pop(&mut self) -> Option<BulkChild> {
        self.pending.pop_front()
    }

    pub(super) fn can_fallback(&self) -> bool {
        self.pages_read == 0 && self.pending.is_empty()
    }

    pub(super) fn read_page(&mut self, fd: libc::c_int) -> io::Result<bool> {
        // One page returns every attribute the scan would otherwise issue one fstatat call per
        // child for. The common-attribute bit numbers also define the in-record packing order.
        let mut attributes = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS
                | ATTR_CMN_ERROR
                | libc::ATTR_CMN_NAME
                | libc::ATTR_CMN_DEVID
                | libc::ATTR_CMN_OBJTYPE
                | libc::ATTR_CMN_FILEID
                | libc::ATTR_CMN_MODTIME
                | libc::ATTR_CMN_CHGTIME
                | libc::ATTR_CMN_ACCESSMASK
                | libc::ATTR_CMN_FLAGS,
            volattr: 0,
            dirattr: 0,
            fileattr: libc::ATTR_FILE_DATALENGTH,
            forkattr: 0,
        };
        let bytes = self.buffer.len() * size_of::<u64>();
        // SAFETY: fd is a live exclusively-owned directory descriptor, attrlist is initialized,
        // and the aligned allocation remains writable for exactly `bytes` during the call.
        let count = unsafe {
            libc::getattrlistbulk(
                fd,
                ptr::from_mut(&mut attributes).cast(),
                self.buffer.as_mut_ptr().cast(),
                bytes,
                0,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(count)
            .map_err(|_| invalid_data("bulk directory count cannot fit usize"))?;
        if count == 0 {
            return Ok(false);
        }
        let bytes = unsafe {
            // SAFETY: Vec<u64> owns initialized storage. The kernel wrote only within this exact
            // allocation, and parsing performs checked offsets for every record and attribute.
            std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), bytes)
        };
        self.pending.extend(parse_attribute_page(bytes, count)?);
        self.pages_read = self
            .pages_read
            .checked_add(1)
            .ok_or_else(|| invalid_data("bulk page count overflow"))?;
        Ok(true)
    }
}

pub(super) fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL) | Some(libc::ENOTSUP) | Some(libc::ENOSYS)
    )
}

/// Parses a page of full child attributes into [`BulkChild`] values.
///
/// Attributes appear in each section in common-bit order. Every read is a checked offset, and
/// an attribute whose data runs past the record fails the whole page rather than producing a
/// partially populated stat.
fn parse_attribute_page(buffer: &[u8], count: usize) -> io::Result<Vec<BulkChild>> {
    let mut result = Vec::with_capacity(count);
    let mut offset = 0usize;
    for _ in 0..count {
        let record_length = usize::try_from(read_unaligned::<u32>(buffer, offset)?)
            .map_err(|_| invalid_data("bulk record length cannot fit usize"))?;
        if record_length < size_of::<u32>() + size_of::<libc::attribute_set_t>()
            || !record_length.is_multiple_of(4)
        {
            return Err(invalid_data("invalid bulk record length"));
        }
        let record_end = offset
            .checked_add(record_length)
            .filter(|end| *end <= buffer.len())
            .ok_or_else(|| invalid_data("bulk record exceeds page"))?;
        let mut cursor = offset + size_of::<u32>();
        let returned = read_unaligned::<libc::attribute_set_t>(buffer, cursor)?;
        cursor += size_of::<libc::attribute_set_t>();
        if returned.commonattr & ATTR_CMN_ERROR != 0 {
            let attribute_error = read_unaligned::<u32>(buffer, cursor)?;
            cursor += size_of::<u32>();
            if attribute_error != 0 {
                return Err(io::Error::from_raw_os_error(attribute_error as i32));
            }
        }
        if returned.commonattr & libc::ATTR_CMN_NAME == 0 {
            return Err(invalid_data("bulk record omitted its name"));
        }
        let reference_offset = cursor;
        let reference = read_unaligned::<libc::attrreference_t>(buffer, cursor)?;
        cursor += size_of::<libc::attrreference_t>();
        let name_start = signed_offset(reference_offset, reference.attr_dataoffset)?;
        let name_length = usize::try_from(reference.attr_length)
            .map_err(|_| invalid_data("bulk name length cannot fit usize"))?;
        let name_end = name_start
            .checked_add(name_length)
            .filter(|end| *end <= record_end)
            .ok_or_else(|| invalid_data("bulk name exceeds its record"))?;
        let name = CStr::from_bytes_until_nul(&buffer[name_start..name_end])
            .map_err(|_| invalid_data("bulk name is not terminated"))?
            .to_bytes();
        // The common attributes follow in common-bit order.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if returned.commonattr & libc::ATTR_CMN_DEVID != 0 {
            // dev_t is a 32-bit value.
            stat.st_dev = i32::from_ne_bytes(read_array(buffer, &mut cursor)?);
        }
        if returned.commonattr & libc::ATTR_CMN_OBJTYPE != 0 {
            // fsobj_type_t is an enum-sized (u32) vnode type; used only to sanity-check mode.
            let obj_type = read_unaligned::<u32>(buffer, cursor)?;
            cursor += size_of::<u32>();
            stat.st_mode = mode_from_vtype(obj_type);
        }
        if returned.commonattr & libc::ATTR_CMN_MODTIME != 0 {
            let modified = read_timespec(buffer, &mut cursor)?;
            stat.st_mtime = modified.0;
            stat.st_mtime_nsec = modified.1;
        }
        if returned.commonattr & libc::ATTR_CMN_CHGTIME != 0 {
            let changed = read_timespec(buffer, &mut cursor)?;
            stat.st_ctime = changed.0;
            stat.st_ctime_nsec = changed.1;
        }
        if returned.commonattr & libc::ATTR_CMN_ACCESSMASK != 0 {
            // mode_t is a 16-bit value; it also carries the type bits.
            let mode = u16::from_ne_bytes(read_array(buffer, &mut cursor)?);
            stat.st_mode = libc::mode_t::from(mode);
            // The next common attribute (FLAGS) is 32-bit, and Darwin pads fixed attributes to
            // their natural alignment within a record. Skipping this pad left every later read
            // two bytes early; the 8-byte file data length then decoded as `real << 16`, which
            // inflated every reported file size by exactly 65536.
            align4(&mut cursor)?;
        }
        if returned.commonattr & libc::ATTR_CMN_FLAGS != 0 {
            stat.st_flags = read_unaligned::<u32>(buffer, cursor)?;
            cursor += size_of::<u32>();
        }
        // OBJID is an fsobj_id_t link/object number, not a stat inode on modern volumes.
        // FILEID supplies the 64-bit file identity, after FLAGS in common-bit packing order.
        // Missing identity cannot become a fabricated zero, even if other fields are present.
        if returned.commonattr & libc::ATTR_CMN_FILEID == 0
            || returned.commonattr & libc::ATTR_CMN_DEVID == 0
        {
            return Err(invalid_data("bulk record omitted its native file identity"));
        }
        stat.st_ino = read_unaligned::<u64>(buffer, cursor)?;
        cursor += size_of::<u64>();
        // The file section follows the common section.
        if returned.fileattr & libc::ATTR_FILE_DATALENGTH != 0 {
            stat.st_size = read_unaligned::<libc::off_t>(buffer, cursor)?;
            cursor += size_of::<libc::off_t>();
        }
        if cursor > record_end {
            return Err(invalid_data("bulk attributes exceeded their record"));
        }

        offset = record_end;
        if name != b"." && name != b".." {
            result.push(BulkChild {
                name: NativeName::unix(name.to_vec()),
                stat,
            });
        }
    }
    Ok(result)
}

/// Maps Darwin's vnode type back to an `st_mode` type mask.
fn mode_from_vtype(obj_type: u32) -> libc::mode_t {
    let type_bits = match obj_type {
        1 => libc::S_IFREG,
        2 => libc::S_IFDIR,
        5 => libc::S_IFLNK,
        3 => libc::S_IFBLK,
        4 => libc::S_IFCHR,
        6 => libc::S_IFSOCK,
        7 => libc::S_IFIFO,
        _ => 0,
    };
    libc::mode_t::from(type_bits)
}

/// Reads a Darwin `struct timespec` (16 bytes on 64-bit: i64 seconds + long nanoseconds).
fn read_timespec(buffer: &[u8], cursor: &mut usize) -> io::Result<(i64, i64)> {
    let seconds = read_unaligned::<i64>(buffer, *cursor)?;
    *cursor = cursor
        .checked_add(size_of::<i64>())
        .ok_or_else(|| invalid_data("timespec offset overflow"))?;
    let nanoseconds = read_unaligned::<libc::c_long>(buffer, *cursor)?;
    *cursor = cursor
        .checked_add(size_of::<libc::c_long>())
        .ok_or_else(|| invalid_data("timespec offset overflow"))?;
    Ok((seconds, nanoseconds as i64))
}

/// Reads a fixed-width array to convert into an integer's native byte representation.
fn read_array<const N: usize>(buffer: &[u8], cursor: &mut usize) -> io::Result<[u8; N]> {
    let value = read_unaligned::<[u8; N]>(buffer, *cursor)?;
    *cursor = cursor
        .checked_add(N)
        .ok_or_else(|| invalid_data("attribute offset overflow"))?;
    Ok(value)
}

/// Rounds `cursor` up to the next 4-byte boundary.
///
/// Darwin attribute records pack fixed-size attributes at natural alignment with a minimum of
/// four bytes. Only the 16-bit ACCESSMASK can leave the cursor on a 2-byte boundary; the value
/// below is the padding bytes, not the next attribute. A checked add keeps a corrupt record
/// length from wrapping the offset.
fn align4(cursor: &mut usize) -> io::Result<()> {
    let aligned = cursor
        .checked_add(3)
        .map(|padded| padded & !3)
        .ok_or_else(|| invalid_data("attribute offset overflow"))?;
    *cursor = aligned;
    Ok(())
}

fn read_unaligned<T: Copy>(buffer: &[u8], offset: usize) -> io::Result<T> {
    let end = offset
        .checked_add(size_of::<T>())
        .filter(|end| *end <= buffer.len())
        .ok_or_else(|| invalid_data("bulk attribute exceeds page"))?;
    let pointer = buffer[offset..end].as_ptr().cast::<T>();
    // SAFETY: the checked range contains size_of::<T>() initialized bytes. Darwin attributes use
    // four-byte packing, so unaligned reads are required for wider integer-bearing structs.
    Ok(unsafe { pointer.read_unaligned() })
}

fn signed_offset(base: usize, relative: i32) -> io::Result<usize> {
    if relative >= 0 {
        base.checked_add(relative as usize)
    } else {
        base.checked_sub(relative.unsigned_abs() as usize)
    }
    .ok_or_else(|| invalid_data("bulk attribute reference overflow"))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(include_file_id: bool) -> Vec<u8> {
        let mut bytes = vec![0; 4];
        let common = libc::ATTR_CMN_NAME
            | libc::ATTR_CMN_DEVID
            | libc::ATTR_CMN_OBJTYPE
            | libc::ATTR_CMN_FLAGS
            | if include_file_id {
                libc::ATTR_CMN_FILEID
            } else {
                0
            };
        for value in [common, 0, 0, libc::ATTR_FILE_DATALENGTH, 0] {
            bytes.extend(value.to_ne_bytes());
        }
        // Name attrreference at byte 24. Payload follows the common and file sections.
        bytes.extend((if include_file_id { 36i32 } else { 28i32 }).to_ne_bytes());
        bytes.extend(4u32.to_ne_bytes());
        bytes.extend(17i32.to_ne_bytes()); // device
        bytes.extend(1u32.to_ne_bytes()); // ordinary file vnode type
        bytes.extend(0u32.to_ne_bytes()); // flags
        if include_file_id {
            bytes.extend(0x123456789abcdeffu64.to_ne_bytes());
        }
        bytes.extend(23i64.to_ne_bytes());
        bytes.extend(b"abc\0");
        let length = bytes.len() as u32;
        bytes[..4].copy_from_slice(&length.to_ne_bytes());
        bytes
    }

    #[test]
    fn decodes_full_width_file_id_after_flags_before_file_data() {
        let parsed = parse_attribute_page(&record(true), 1).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, NativeName::unix(b"abc".to_vec()));
        assert_eq!(parsed[0].stat.st_ino, 0x123456789abcdeff);
        assert_eq!(parsed[0].stat.st_dev, 17);
        assert_eq!(parsed[0].stat.st_size, 23);
    }

    #[test]
    fn omitted_file_id_cannot_become_a_zero_native_identity() {
        let error = parse_attribute_page(&record(false), 1).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
