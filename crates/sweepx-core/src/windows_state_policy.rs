//! Portable parsing of the narrow DACL contract used for private Windows state.
//!
//! A grant with an unfamiliar layout is not a deny. Accept only ordinary allow/deny ACEs,
//! validate their SID boundaries, and refuse every other type instead of guessing its effect.
//! Native callers supply the bounded ACL bytes returned by Windows, never a persisted verdict.

/// Whether every grant in a complete ACL names an admitted principal.
///
/// Null ACLs are rejected by the native caller before reaching this function. Empty ACLs grant
/// nobody access and are private; unsupported revisions, truncated ACEs and unknown types fail
/// closed. This is a privacy check, not an access check or proof that the caller owns the object.
pub(crate) fn is_private_acl(bytes: &[u8], trusted: &[&[u8]]) -> bool {
    if bytes.len() < 8 || !matches!(bytes[0], 2 | 4) || !trusted.iter().all(|sid| valid_sid(sid)) {
        return false;
    }
    let size = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    let count = u16::from_le_bytes([bytes[4], bytes[5]]);
    if size < 8 || size > bytes.len() {
        return false;
    }
    let mut offset = 8usize;
    for _ in 0..count {
        let Some(header) = bytes.get(offset..size).and_then(|rest| rest.get(..4)) else {
            return false;
        };
        // Object/callback/conditional allow ACEs can also grant access. Their unsupported
        // layouts must never be silently skipped, even if another basic allow looks private.
        if !matches!(header[0], 0 | 1) {
            return false;
        }
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let Some(end) = offset.checked_add(length).filter(|end| *end <= size) else {
            return false;
        };
        let Some(sid) = bytes.get(offset..end).and_then(|ace| ace.get(8..)) else {
            return false;
        };
        if !valid_sid(sid) || (header[0] == 0 && !trusted.contains(&sid)) {
            return false;
        }
        offset = end;
    }
    true
}

/// Pointer-aligned token storage admission, limited to 256 KiB per native observation.
/// Zero or excessive OS-reported sizes are errors, not empty answers or unbounded allocations.
pub(crate) fn token_buffer_words(bytes: u32) -> Option<usize> {
    if !(1..=256 * 1024).contains(&bytes) {
        return None;
    }
    Some((bytes as usize).div_ceil(size_of::<usize>()))
}

/// Materializes at most 32,767 native UTF-16 units plus an SDK terminator.
/// Embedded NULs are refused rather than sending a truncated name to Windows. Other units,
/// including unpaired surrogates, remain lossless; this is encoding admission, not path safety.
pub(crate) fn terminated_utf16(units: impl Iterator<Item = u16>) -> Option<Vec<u16>> {
    let mut buffer = Vec::new();
    for unit in units.take(32_768) {
        if unit == 0 || buffer.len() == 32_767 {
            return None;
        }
        buffer.push(unit);
    }
    buffer.push(0);
    Some(buffer)
}

fn valid_sid(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15 && sid.len() == 8 + usize::from(sid[1]) * 4
}

#[cfg(test)]
mod tests {
    use super::*;

    // Literal SID/ACL byte fixtures follow the documented little-endian ACL/ACE fields.
    // S-1-5-18 (SYSTEM), S-1-5-32-544 (Administrators), and S-1-1-0 (Everyone).
    const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    const ADMIN: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
    const EVERYONE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    const SYSTEM_ACL: &[u8] = &[
        2, 0, 28, 0, 1, 0, 0, 0, // ACL revision, length and ACE count
        0, 0, 20, 0, 255, 1, 31, 0, // basic allow, size, FILE_ALL_ACCESS
        1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
    ];

    #[test]
    fn literal_private_grants_and_empty_acl_are_admitted() {
        assert!(is_private_acl(SYSTEM_ACL, &[SYSTEM, ADMIN]));
        assert!(is_private_acl(&[2, 0, 8, 0, 0, 0, 0, 0], &[SYSTEM]));
        let admin_acl = [
            2, 0, 32, 0, 1, 0, 0, 0, 0, 0, 24, 0, 255, 1, 31, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0,
            0, 32, 2, 0, 0,
        ];
        assert!(is_private_acl(&admin_acl, &[SYSTEM, ADMIN]));
    }

    #[test]
    fn foreign_grants_are_refused_but_foreign_denials_are_private() {
        let everyone_allow = [
            2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        assert!(!is_private_acl(&everyone_allow, &[SYSTEM, ADMIN]));
        assert!(is_private_acl(&everyone_allow, &[EVERYONE]));
        let mut everyone_deny = everyone_allow;
        everyone_deny[8] = 1;
        assert!(is_private_acl(&everyone_deny, &[SYSTEM, ADMIN]));
    }

    #[test]
    fn unknown_grant_layouts_never_disappear_from_the_privacy_decision() {
        // ACCESS_ALLOWED_OBJECT, ACCESS_ALLOWED_CALLBACK and object callback types.
        for ace_type in [5, 9, 11, 255] {
            let mut acl = SYSTEM_ACL.to_vec();
            acl[8] = ace_type;
            assert!(!is_private_acl(&acl, &[SYSTEM]), "type {ace_type}");
        }
    }

    #[test]
    fn a_private_basic_grant_cannot_hide_a_later_unknown_grant() {
        let mut acl = SYSTEM_ACL.to_vec();
        acl[2] = 48;
        acl[4] = 2;
        acl.extend_from_slice(&[9, 0, 20, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert!(!is_private_acl(&acl, &[SYSTEM]));
    }

    #[test]
    fn malformed_acl_and_sid_boundaries_are_refused_without_panics() {
        for end in 0..SYSTEM_ACL.len() {
            assert!(!is_private_acl(&SYSTEM_ACL[..end], &[SYSTEM]));
        }
        for (offset, value) in [
            (0, 3),
            (2, 7),
            (4, 2),
            (10, 0),
            (10, 255),
            (16, 2),
            (17, 16),
        ] {
            let mut acl = SYSTEM_ACL.to_vec();
            acl[offset] = value;
            assert!(!is_private_acl(&acl, &[SYSTEM]), "offset {offset}");
        }
        assert!(!is_private_acl(SYSTEM_ACL, &[&SYSTEM[..11]]));
    }

    #[test]
    fn token_storage_has_nonzero_bounded_aligned_admission() {
        assert!(token_buffer_words(0).is_none());
        assert_eq!(token_buffer_words(1), Some(1));
        assert!(token_buffer_words(262_144).is_some());
        assert!(token_buffer_words(262_145).is_none());
        assert!(token_buffer_words(u32::MAX).is_none());
    }

    #[test]
    fn native_text_admission_is_bounded_and_preserves_opaque_units() {
        assert_eq!(
            terminated_utf16([65, 0xd800, 66].into_iter()),
            Some(vec![65, 0xd800, 66, 0])
        );
        assert!(terminated_utf16([65, 0, 66].into_iter()).is_none());
        assert_eq!(
            terminated_utf16(std::iter::repeat_n(65, 32_767))
                .unwrap()
                .len(),
            32_768
        );
        let mut observed = 0;
        let giant = std::iter::repeat_n(65, 1_000_000).inspect(|_| observed += 1);
        assert!(terminated_utf16(giant).is_none());
        assert_eq!(observed, 32_768);
    }
}
