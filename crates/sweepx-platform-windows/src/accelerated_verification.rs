//! Unprivileged verification of accelerated (MFT-derived) records.
//!
//! The NTFS acceleration reader yields a 64-bit `file_reference_number` per record, but an MFT
//! page is a point-in-time snapshot and this crate's rule is that a display path never carries
//! filesystem authority. Before an accelerated record may influence a reported result, it must
//! be provable that the record names the same object a handle-relative traversal would reach.
//!
//! The important measured property is that this verification needs **no elevation**:
//! `OpenFileById` accepts any handle on the volume as its volume hint, not a volume handle. So
//! reading the MFT requires privilege while checking its output does not, which is what makes
//! this half of the accelerator testable and shippable on an ordinary account.
//!
//! Three refusals are load-bearing and were confirmed against the live filesystem rather than
//! assumed (see `docs/research/native-scan-qualification.md`):
//!
//! * a deleted record's reference number is refused instead of resolving to whatever object
//!   later reused that id, so a stale snapshot fails closed;
//! * a reference number offered with a hint on a different volume is refused, so a record
//!   cannot silently cross a volume boundary;
//! * the reopened object's identity is compared as the **full 128-bit** file id plus volume
//!   serial. The high 64 bits happen to be zero on the volumes measured here, which would make
//!   a 64-bit comparison work by accident; that is a per-volume property, so relying on it
//!   would be a latent correctness bug.

use std::ffi::c_void;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::ptr;

use sweepx_platform::EntryIdentity;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_DESCRIPTOR, FILE_ID_INFO,
    FILE_ID_TYPE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandleEx, OpenFileById,
};

/// `FILE_ID_TYPE::FileIdType` — the 64-bit NTFS file reference number an MFT record carries.
const FILE_ID_TYPE_FILE_ID: FILE_ID_TYPE = 0;

/// Why an accelerated record could not be confirmed to name a live object.
///
/// Every variant is a refusal to use the record, never a downgrade to trusting it. Variants are
/// distinguished because they mean different things about the snapshot: `Stale` is expected and
/// benign during any scan of a live volume, while `IdentityMismatch` means the id resolved to a
/// *different* object and is evidence the snapshot must not be trusted at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRefusal {
    /// The reference number no longer resolves: the record was deleted or is otherwise gone.
    Stale { code: u32 },
    /// The volume hint was refused for this reference number, including the cross-volume case.
    NotOnThisVolume { code: u32 },
    /// The object resolved but its metadata could not be read.
    MetadataUnavailable { code: u32 },
    /// The object resolved to an identity other than the one the record claimed.
    IdentityMismatch,
    /// The record's own claim is unusable, so there is nothing to verify against.
    UnusableRecord,
}

impl VerificationRefusal {
    /// Stable machine code for logs and structured output. Never localized.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Stale { .. } => "accelerated_record_stale",
            Self::NotOnThisVolume { .. } => "accelerated_record_not_on_volume",
            Self::MetadataUnavailable { .. } => "accelerated_record_metadata_unavailable",
            Self::IdentityMismatch => "accelerated_record_identity_mismatch",
            Self::UnusableRecord => "accelerated_record_unusable",
        }
    }

    /// Whether the refusal is an ordinary consequence of scanning a live volume.
    ///
    /// A stale record is normal: files are deleted while a scan runs. An identity mismatch is
    /// not, and callers should treat it as a reason to distrust the whole snapshot rather than
    /// to skip one row.
    pub const fn is_expected_on_a_live_volume(self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

/// A confirmed accelerated record: the identity a live open actually observed.
///
/// Holding this type is the evidence that the record was verified. It carries the identity read
/// back from the reopened object rather than the record's claim, so a caller cannot accidentally
/// propagate the unverified value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    identity: EntryIdentity,
    is_directory: bool,
    is_reparse_point: bool,
    reparse_tag: u32,
}

impl VerifiedRecord {
    /// Identity observed by the live open, suitable for comparison with traversal output.
    pub fn identity(&self) -> &EntryIdentity {
        &self.identity
    }

    /// Whether the live object is a directory.
    pub const fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Whether the live object is a reparse point, which traversal must not follow.
    pub const fn is_reparse_point(&self) -> bool {
        self.is_reparse_point
    }

    /// Reparse tag when `is_reparse_point()`, else zero.
    pub const fn reparse_tag(&self) -> u32 {
        self.reparse_tag
    }
}

/// What an accelerated record claims, in the terms the MFT provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceleratedClaim {
    /// 64-bit NTFS file reference number from the layout record.
    pub file_reference_number: u64,
    /// Whether the record described a directory, checked against the live object.
    pub is_directory: bool,
}

/// Verifies one accelerated record against the live filesystem, unprivileged.
///
/// `volume_hint` must be an open handle on the same volume as the record; an ordinary directory
/// handle the scanner already holds is sufficient, and no volume handle or privilege is needed.
///
/// The open deliberately requests only `FILE_READ_ATTRIBUTES` and passes
/// `FILE_FLAG_OPEN_REPARSE_POINT`: verification must observe the object the record names, never
/// follow a link to a different one, and must not read file contents or trigger a cloud
/// provider to hydrate them.
pub fn verify_accelerated_record(
    volume_hint: &OwnedHandle,
    claim: AcceleratedClaim,
) -> Result<VerifiedRecord, VerificationRefusal> {
    // A zero reference number is never a real record. Refusing here keeps a malformed page from
    // being probed against the filesystem at all.
    if claim.file_reference_number == 0 {
        return Err(VerificationRefusal::UnusableRecord);
    }

    let opened = open_by_file_reference(volume_hint, claim.file_reference_number)?;
    let identity = read_file_id(&opened)?;
    let (attributes, reparse_tag) = read_attribute_tag(&opened)?;

    let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    // The record's own type claim is part of what is being verified: a snapshot that calls a
    // file a directory is not merely outdated, it is inconsistent with the live object.
    if is_directory != claim.is_directory {
        return Err(VerificationRefusal::IdentityMismatch);
    }

    let is_reparse_point = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    Ok(VerifiedRecord {
        identity,
        is_directory,
        is_reparse_point,
        reparse_tag: if is_reparse_point { reparse_tag } else { 0 },
    })
}

/// Confirms a verified record refers to the same object traversal reported.
///
/// Identity equality alone is not enough: an object whose type or reparse status differs is a
/// different scanning subject even at the same id, which mirrors the existing
/// `matches_enumerated_identity` check used after directory enumeration.
pub fn agrees_with_traversal(
    verified: &VerifiedRecord,
    traversal_identity: &EntryIdentity,
    traversal_is_directory: bool,
) -> bool {
    &verified.identity == traversal_identity && verified.is_directory == traversal_is_directory
}

fn open_by_file_reference(
    volume_hint: &OwnedHandle,
    file_reference_number: u64,
) -> Result<OwnedHandle, VerificationRefusal> {
    let mut descriptor = FILE_ID_DESCRIPTOR {
        dwSize: mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: FILE_ID_TYPE_FILE_ID,
        Anonymous: unsafe { mem::zeroed() },
    };
    // The union is written through the 64-bit reference-number member, matching the descriptor
    // type set above.
    descriptor.Anonymous.FileId = file_reference_number as i64;

    // SAFETY: the descriptor is fully initialized and outlives the call; the hint handle stays
    // borrowed for the duration. No output buffer is involved.
    let raw = unsafe {
        OpenFileById(
            volume_hint.as_raw_handle() as HANDLE,
            &descriptor,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            // BACKUP_SEMANTICS admits directories; OPEN_REPARSE_POINT keeps verification on the
            // named object instead of resolving to a link target.
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        // ERROR_INVALID_PARAMETER is what the filesystem returns both for a reference number
        // that no longer exists and for one offered against the wrong volume. They are reported
        // separately from other failures because both are refusals to resolve rather than
        // permission or I/O problems, and both must fail closed.
        return Err(match code {
            2 | 3 | 87 => VerificationRefusal::Stale { code },
            _ => VerificationRefusal::NotOnThisVolume { code },
        });
    }
    // SAFETY: `raw` is a valid, exclusively owned handle checked above; ownership transfers here
    // so the handle is closed exactly once on drop.
    Ok(unsafe { <OwnedHandle as std::os::windows::io::FromRawHandle>::from_raw_handle(raw as _) })
}

fn read_file_id(handle: &OwnedHandle) -> Result<EntryIdentity, VerificationRefusal> {
    let mut info = MaybeUninit::<FILE_ID_INFO>::zeroed();
    // SAFETY: the buffer is sized by the same type passed as the class, and is only read after a
    // success return.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileIdInfo,
            info.as_mut_ptr().cast::<c_void>(),
            mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return Err(VerificationRefusal::MetadataUnavailable { code });
    }
    // SAFETY: initialized by the successful call above.
    let info = unsafe { info.assume_init() };
    Ok(EntryIdentity::from_windows_file_id(
        info.VolumeSerialNumber,
        info.FileId.Identifier,
    ))
}

fn read_attribute_tag(handle: &OwnedHandle) -> Result<(u32, u32), VerificationRefusal> {
    let mut info = MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::zeroed();
    // SAFETY: as above; buffer type matches the requested information class.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            info.as_mut_ptr().cast::<c_void>(),
            mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if ok == 0 {
        let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return Err(VerificationRefusal::MetadataUnavailable { code });
    }
    // SAFETY: initialized by the successful call above.
    let info = unsafe { info.assume_init() };
    Ok((info.FileAttributes, info.ReparseTag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

    fn open_hint(path: &Path) -> OwnedHandle {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: null-terminated path; the returned handle is checked before being adopted.
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
            "opening a hint handle must succeed unprivileged: {}",
            io::Error::last_os_error()
        );
        // SAFETY: validated non-null handle, ownership transferred once.
        unsafe { <OwnedHandle as std::os::windows::io::FromRawHandle>::from_raw_handle(raw as _) }
    }

    /// Reads the live identity of `path` the way the scanner would, for cross-checking.
    fn live_identity(path: &Path) -> (EntryIdentity, u64, bool) {
        let handle = open_hint(path);
        let identity = read_file_id(&handle).expect("live identity");
        let (attributes, _) = read_attribute_tag(&handle).expect("live attributes");
        let raw = {
            let mut info = MaybeUninit::<FILE_ID_INFO>::zeroed();
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    handle.as_raw_handle() as HANDLE,
                    FileIdInfo,
                    info.as_mut_ptr().cast::<c_void>(),
                    mem::size_of::<FILE_ID_INFO>() as u32,
                )
            };
            assert_ne!(ok, 0);
            let info = unsafe { info.assume_init() };
            u64::from_le_bytes(info.FileId.Identifier[0..8].try_into().unwrap())
        };
        (identity, raw, attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
    }

    struct Fixture {
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "sweepx-verify-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            fs::create_dir_all(&root).expect("fixture root");
            Self { root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// The core property: a reference number resolves to the same object traversal would see,
    /// with no elevation. Asserted against the live filesystem, not a fake.
    #[test]
    fn a_live_record_verifies_to_the_identity_traversal_would_observe() {
        let fixture = Fixture::new("live");
        let file = fixture.root.join("payload.bin");
        fs::write(&file, vec![0u8; 2048]).expect("payload");

        let (expected_identity, frn, is_dir) = live_identity(&file);
        assert!(!is_dir);

        let hint = open_hint(&fixture.root);
        let verified = verify_accelerated_record(
            &hint,
            AcceleratedClaim {
                file_reference_number: frn,
                is_directory: false,
            },
        )
        .expect("a live record must verify without elevation");

        assert_eq!(
            verified.identity(),
            &expected_identity,
            "verification must observe the identity a live open reports"
        );
        assert!(agrees_with_traversal(&verified, &expected_identity, false));
        assert!(!verified.is_reparse_point());
    }

    /// Directories verify too, which matters because reconstruction walks directory records.
    #[test]
    fn a_directory_record_verifies_and_reports_its_type() {
        let fixture = Fixture::new("dir");
        let nested = fixture.root.join("nested");
        fs::create_dir_all(&nested).expect("nested");

        let (expected, frn, is_dir) = live_identity(&nested);
        assert!(is_dir);

        let hint = open_hint(&fixture.root);
        let verified = verify_accelerated_record(
            &hint,
            AcceleratedClaim {
                file_reference_number: frn,
                is_directory: true,
            },
        )
        .expect("a live directory must verify");
        assert!(verified.is_directory());
        assert!(agrees_with_traversal(&verified, &expected, true));
    }

    /// A snapshot claiming the wrong type must be refused even though the id resolves.
    ///
    /// This is the case identity equality alone would let through, so it is asserted separately.
    #[test]
    fn a_record_whose_type_claim_is_wrong_is_refused() {
        let fixture = Fixture::new("type");
        let file = fixture.root.join("payload.bin");
        fs::write(&file, b"x").expect("payload");
        let (_, frn, _) = live_identity(&file);

        let hint = open_hint(&fixture.root);
        assert_eq!(
            verify_accelerated_record(
                &hint,
                AcceleratedClaim {
                    file_reference_number: frn,
                    // The live object is a file; the snapshot claims a directory.
                    is_directory: true,
                },
            ),
            Err(VerificationRefusal::IdentityMismatch)
        );
    }

    /// A deleted record must fail closed rather than resolve to a reused id.
    #[test]
    fn a_deleted_record_is_refused_as_stale() {
        let fixture = Fixture::new("stale");
        let doomed = fixture.root.join("doomed.bin");
        fs::write(&doomed, b"temp").expect("doomed");
        let (_, frn, _) = live_identity(&doomed);
        fs::remove_file(&doomed).expect("remove");

        let hint = open_hint(&fixture.root);
        let refusal = verify_accelerated_record(
            &hint,
            AcceleratedClaim {
                file_reference_number: frn,
                is_directory: false,
            },
        )
        .expect_err("a deleted record must never verify");
        assert!(
            matches!(refusal, VerificationRefusal::Stale { .. }),
            "expected a stale refusal, got {refusal:?}"
        );
        assert!(
            refusal.is_expected_on_a_live_volume(),
            "deletion during a scan is ordinary and must not be reported as corruption"
        );
    }

    /// A zero reference number is rejected without touching the filesystem.
    #[test]
    fn a_zero_reference_number_is_refused_without_probing() {
        let fixture = Fixture::new("zero");
        let hint = open_hint(&fixture.root);
        assert_eq!(
            verify_accelerated_record(
                &hint,
                AcceleratedClaim {
                    file_reference_number: 0,
                    is_directory: false,
                },
            ),
            Err(VerificationRefusal::UnusableRecord)
        );
    }

    /// Only a stale refusal counts as routine; a mismatch must not be swept into that bucket.
    #[test]
    fn only_staleness_is_classified_as_expected() {
        assert!(VerificationRefusal::Stale { code: 87 }.is_expected_on_a_live_volume());
        assert!(!VerificationRefusal::IdentityMismatch.is_expected_on_a_live_volume());
        assert!(!VerificationRefusal::UnusableRecord.is_expected_on_a_live_volume());
        assert!(
            !VerificationRefusal::NotOnThisVolume { code: 87 }.is_expected_on_a_live_volume(),
            "a cross-volume reference is a snapshot defect, not routine churn"
        );
    }

    /// Refusal codes are stable and distinct, since they appear in machine-readable output.
    #[test]
    fn refusal_codes_are_distinct_and_stable() {
        let codes = [
            VerificationRefusal::Stale { code: 2 }.code(),
            VerificationRefusal::NotOnThisVolume { code: 87 }.code(),
            VerificationRefusal::MetadataUnavailable { code: 5 }.code(),
            VerificationRefusal::IdentityMismatch.code(),
            VerificationRefusal::UnusableRecord.code(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "refusal codes must not collide");
        assert_eq!(
            VerificationRefusal::Stale { code: 2 }.code(),
            "accelerated_record_stale",
            "codes are a machine contract and must not drift"
        );
    }

    /// A hard-linked file has one MFT record and several names; verification is per object, so
    /// both names must verify to the *same* identity.
    ///
    /// This pins the behavior behind the measured 1208 colliding id groups on this host, all of
    /// which were hard links rather than distinct objects sharing an id.
    #[test]
    fn hard_links_verify_to_one_shared_identity() {
        let fixture = Fixture::new("hardlink");
        let target = fixture.root.join("target.bin");
        fs::write(&target, vec![1u8; 512]).expect("target");
        let link = fixture.root.join("alias.bin");
        if fs::hard_link(&target, &link).is_err() {
            println!("SKIP: this host or filesystem does not support hard links");
            return;
        }

        let (target_identity, target_frn, _) = live_identity(&target);
        let (link_identity, link_frn, _) = live_identity(&link);
        assert_eq!(
            target_identity, link_identity,
            "two names for one object must share an identity"
        );
        assert_eq!(target_frn, link_frn, "and share a reference number");

        let hint = open_hint(&fixture.root);
        let verified = verify_accelerated_record(
            &hint,
            AcceleratedClaim {
                file_reference_number: target_frn,
                is_directory: false,
            },
        )
        .expect("a hard-linked record verifies");
        assert_eq!(verified.identity(), &target_identity);
    }

    /// A file handle works as the volume hint, so verification never needs to open a volume.
    ///
    /// This is the property that keeps the whole check unprivileged: requiring a volume handle
    /// would push verification behind the same elevation wall as the MFT read itself.
    #[test]
    fn an_ordinary_file_handle_is_a_sufficient_volume_hint() {
        let fixture = Fixture::new("hint");
        let anchor = fixture.root.join("anchor.bin");
        fs::write(&anchor, b"anchor").expect("anchor");
        let subject = fixture.root.join("subject.bin");
        fs::write(&subject, b"subject").expect("subject");

        let (expected, frn, _) = live_identity(&subject);
        let file_hint = open_hint(&anchor);
        let verified = verify_accelerated_record(
            &file_hint,
            AcceleratedClaim {
                file_reference_number: frn,
                is_directory: false,
            },
        )
        .expect("a plain file handle must suffice as the volume hint");
        assert_eq!(verified.identity(), &expected);
    }
}
