//! Bounded decoding of FILE_NAMES_INFORMATION pages; no native pointers escape this parser.

use std::io;

/// Walks the documented 12-byte header and counted UTF-16 name, charging even unknown names.
/// Cache basenames are ASCII. Other names are ignored without lossy replacement or large copies.
pub(super) fn visit_names(
    bytes: &[u8],
    remaining: &mut usize,
    mut visit: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(io::Error::other("invalid cache directory page size"));
    }
    let mut offset = 0;
    loop {
        let entry = bytes.get(offset..).ok_or_else(malformed)?;
        let header = entry.get(..12).ok_or_else(malformed)?;
        let next = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        if length == 0 || !length.is_multiple_of(2) {
            return Err(malformed());
        }
        let end = 12usize.checked_add(length).ok_or_else(malformed)?;
        let name = entry.get(12..end).ok_or_else(malformed)?;
        if next != 0 && (!next.is_multiple_of(4) || next < end || next >= entry.len()) {
            return Err(malformed());
        }
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("cache enumeration budget exceeded"))?;
        // A Windows component may contain unpaired surrogates. It cannot be one of our ASCII
        // managed names, so do not invent another spelling or deserialize it as cache authority.
        if name.len() <= 510
            && name
                .as_chunks::<2>()
                .0
                .iter()
                .all(|unit| unit[1] == 0 && unit[0] < 128)
        {
            let text: String = name
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| char::from(unit[0]))
                .collect();
            visit(&text)?;
        }
        if next == 0 {
            return Ok(());
        }
        offset += next;
    }
}

fn malformed() -> io::Error {
    io::Error::other("malformed cache directory page")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Literal SDK layout oracle: next offset, file index, byte length, UTF-16 name.
    const TWO: &[u8] = &[
        16, 0, 0, 0, 91, 0, 0, 0, 2, 0, 0, 0, b'a', 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 2, 0, 0, 0,
        b'b', 0,
    ];

    #[test]
    fn literal_pages_preserve_names_and_charge_unknown_native_names() {
        let mut names = Vec::new();
        let mut budget = 2;
        visit_names(TWO, &mut budget, |name| {
            names.push(name.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(names, ["a", "b"]);
        assert_eq!(budget, 0);
        let surrogate = [0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0xd8];
        visit_names(&surrogate, &mut 1, |_| {
            panic!("unknown native name is not managed")
        })
        .unwrap();
        assert!(visit_names(&surrogate, &mut 0, |_| Ok(())).is_err());
    }

    #[test]
    fn truncated_overlapping_unaligned_and_excessive_pages_fail_closed() {
        for length in [0, 1, 11, 13, 16, 27, 29] {
            assert!(
                visit_names(&TWO[..length], &mut 10, |_| Ok(())).is_err(),
                "{length}"
            );
        }
        for next in [4u32, 15, 29, 30, u32::MAX] {
            let mut page = TWO.to_vec();
            page[..4].copy_from_slice(&next.to_le_bytes());
            assert!(visit_names(&page, &mut 10, |_| Ok(())).is_err());
        }
        for length in [0u32, 1, 65536, u32::MAX] {
            let mut page = TWO.to_vec();
            page[8..12].copy_from_slice(&length.to_le_bytes());
            assert!(visit_names(&page, &mut 10, |_| Ok(())).is_err());
        }
        assert!(visit_names(TWO, &mut 1, |_| Ok(())).is_err());
        assert!(visit_names(&vec![0; 65537], &mut 10, |_| Ok(())).is_err());
    }
}
