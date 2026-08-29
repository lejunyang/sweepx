use std::collections::VecDeque;
use std::ffi::CStr;
use std::io;
use std::mem::size_of;
use std::ptr;

use sweepx_model::NativeName;

const ATTR_CMN_ERROR: libc::attrgroup_t = 0x2000_0000;
const DIRECTORY_BUFFER_BYTES: usize = 64 * 1024;

/// Bounded state for Darwin's paged directory-attribute API.
#[derive(Debug)]
pub(super) struct BulkDirectoryCursor {
    buffer: Vec<u64>,
    pending: VecDeque<NativeName>,
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

    pub(super) fn pop(&mut self) -> Option<NativeName> {
        self.pending.pop_front()
    }

    pub(super) fn can_fallback(&self) -> bool {
        self.pages_read == 0 && self.pending.is_empty()
    }

    pub(super) fn read_page(&mut self, fd: libc::c_int) -> io::Result<bool> {
        let mut attributes = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR | libc::ATTR_CMN_NAME,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
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
        self.pending.extend(parse_name_page(bytes, count)?);
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

fn parse_name_page(buffer: &[u8], count: usize) -> io::Result<Vec<NativeName>> {
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
        if name != b"." && name != b".." {
            result.push(NativeName::unix(name.to_vec()));
        }
        offset = record_end;
    }
    Ok(result)
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
