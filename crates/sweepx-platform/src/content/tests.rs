use super::*;
use crate::{EntryIdentity, EntryKind, FilesystemIdentity, MountIdentity, RegularFileChangeStamp};

fn name(value: &str) -> NativeName {
    #[cfg(unix)]
    {
        NativeName::unix(value.as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        NativeName::windows_utf16(value.encode_utf16().collect::<Vec<_>>())
    }
}

fn observation(length: usize) -> RegularFileObservation {
    RegularFileObservation {
        kind: EntryKind::File,
        identity: EntryIdentity::from_unix(3, 7),
        filesystem_identity: FilesystemIdentity { device: 3 },
        mount_identity: MountIdentity { value: 41 },
        logical_bytes: (length as u128).into(),
        change_stamp: RegularFileChangeStamp::new([4, 9]),
    }
}

fn request(
    offset: u64,
    count: u64,
    previous: Option<RegularFileObservation>,
) -> RegularFileStreamRequest {
    RegularFileStreamRequest::new(
        name("file"),
        RegularFileReadExpectation::EstablishLive,
        offset,
        count,
        previous,
    )
    .unwrap()
}

#[test]
fn ranged_stream_matches_an_independent_slice_with_short_native_reads() {
    let contents: Vec<_> = (0..250_113).map(|i| (i % 251) as u8).collect();
    let before = observation(contents.len());
    let mut got = Vec::new();
    let mut largest = 0;
    let mut positions = Vec::new();
    let result = stream_observed_file(
        &request(11, 200_079, None),
        &CancellationToken::new(),
        before.clone(),
        |offset, out| {
            largest = largest.max(out.len());
            positions.push(offset);
            let count = out.len().min(17_001);
            out[..count].copy_from_slice(&contents[offset as usize..offset as usize + count]);
            Ok(count)
        },
        || Ok(before),
        &mut |chunk| {
            got.extend_from_slice(chunk);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(got, contents[11..200_090]);
    assert_eq!(result.bytes_read, 200_079);
    assert!(largest <= 65_536);
    assert!(positions.len() > 3);
    assert_eq!(positions[0], 11);
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn prior_stamp_identity_and_mount_are_checked_before_any_read() {
    for mutate in [0, 1, 2, 3] {
        let before = observation(4);
        let mut stale = before.clone();
        match mutate {
            0 => stale.change_stamp = RegularFileChangeStamp::new([8]),
            1 => stale.identity = EntryIdentity::from_unix(3, 8),
            2 => stale.mount_identity.value += 1,
            _ => stale.logical_bytes = 5.into(),
        }
        let error = stream_observed_file(
            &request(0, 4, Some(stale)),
            &CancellationToken::new(),
            before,
            |_, _| panic!("stale stage read payload"),
            || panic!("stale stage completed"),
            &mut |_| panic!("stale stage emitted bytes"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            BoundedRegularFileReadError::ChangedDuringRead(_)
        ));
    }
    let expected = RegularFileReadExpectation::previously_observed(
        EntryIdentity::from_unix(3, 99),
        FilesystemIdentity { device: 3 },
        MountIdentity { value: 41 },
    );
    let bound = RegularFileStreamRequest::new(name("file"), expected, 0, 4, None).unwrap();
    assert!(matches!(
        stream_observed_file(
            &bound,
            &CancellationToken::new(),
            observation(4),
            |_, _| panic!("wrong identity read"),
            || panic!(),
            &mut |_| panic!()
        ),
        Err(BoundedRegularFileReadError::IdentityMismatch(_))
    ));
}

#[test]
fn changes_early_eof_and_bad_chunk_counts_never_return_success() {
    let before = observation(4);
    let mut after = before.clone();
    after.change_stamp = RegularFileChangeStamp::new([99]);
    assert!(matches!(
        stream_observed_file(
            &request(0, 4, None),
            &CancellationToken::new(),
            before.clone(),
            |_, out| {
                out.fill(7);
                Ok(out.len())
            },
            || Ok(after),
            &mut |_| Ok(())
        ),
        Err(BoundedRegularFileReadError::ChangedDuringRead(_))
    ));
    for invalid in [0, 5] {
        assert!(
            stream_observed_file(
                &request(0, 4, None),
                &CancellationToken::new(),
                before.clone(),
                |_, _| Ok(invalid),
                || Ok(before.clone()),
                &mut |_| panic!("bad native count emitted bytes")
            )
            .is_err()
        );
    }
}

#[test]
fn cancellation_and_consumer_error_stop_before_more_io() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        stream_observed_file(
            &request(0, 4, None),
            &cancel,
            observation(4),
            |_, _| panic!(),
            || panic!(),
            &mut |_| panic!()
        ),
        Err(BoundedRegularFileReadError::Cancelled)
    ));
    let cancel = CancellationToken::new();
    let mut calls = 0;
    let error = stream_observed_file(
        &request(0, 200_000, None),
        &cancel,
        observation(200_000),
        |_, out| {
            calls += 1;
            out.fill(1);
            Ok(out.len())
        },
        || panic!("cancelled stream finalized"),
        &mut |_| {
            cancel.cancel();
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error, BoundedRegularFileReadError::Cancelled);
    assert_eq!(calls, 1);
    let refusal = BoundedRegularFileReadError::Unsupported("IO budget exhausted".into());
    assert_eq!(
        stream_observed_file(
            &request(0, 4, None),
            &CancellationToken::new(),
            observation(4),
            |_, out| Ok(out.len()),
            || panic!(),
            &mut |_| Err(refusal.clone())
        )
        .unwrap_err(),
        refusal
    );
}

#[test]
fn names_ranges_zero_length_and_eof_are_explicit() {
    assert!(
        RegularFileStreamRequest::new(
            name("../escape"),
            RegularFileReadExpectation::EstablishLive,
            0,
            4,
            None
        )
        .is_err()
    );
    for (offset, count) in [(u64::MAX, 2), (0, u64::MAX), (i64::MAX as u64, 1)] {
        assert!(
            RegularFileStreamRequest::new(
                name("file"),
                RegularFileReadExpectation::EstablishLive,
                offset,
                count,
                None
            )
            .is_err()
        );
    }
    for (size, offset, count) in [(0, 0, 100), (4, 4, 100), (4, 9, 100), (4, 0, 0)] {
        let before = observation(size);
        let result = stream_observed_file(
            &request(offset, count, None),
            &CancellationToken::new(),
            before.clone(),
            |_, _| panic!("empty range read"),
            || Ok(before),
            &mut |_| panic!("empty range emitted"),
        )
        .unwrap();
        assert_eq!(result.bytes_read, 0);
    }
}

struct FaultyBackend(u8);
impl PlatformScanner for FaultyBackend {
    type DirectoryHandle = ();
    fn platform_name(&self) -> &'static str {
        "faulty-content"
    }
    fn admit_root(
        &self,
        _: &crate::ScanRoot,
        _: &CancellationToken,
    ) -> Result<crate::RootAdmission<()>, crate::PlatformError> {
        unreachable!()
    }
    fn enumerate_children(
        &self,
        _: &mut (),
        _: &CancellationToken,
        _: crate::DirectoryReadLimits,
    ) -> Result<crate::DirectoryEntryBatch, crate::PlatformError> {
        unreachable!()
    }
    fn inspect_child(
        &self,
        _: &(),
        _: &crate::DirectoryEntryRecord,
        _: &CancellationToken,
    ) -> Result<crate::WalkEntry<()>, crate::PlatformError> {
        unreachable!()
    }
    fn inspect_child_with_directory_admission(
        &self,
        _: &(),
        _: &crate::DirectoryEntryRecord,
        _: &CancellationToken,
        _: crate::DirectoryHandleAdmission,
    ) -> Result<crate::WalkEntry<()>, crate::PlatformError> {
        unreachable!()
    }
    fn is_same_mount(
        &self,
        _: &crate::EntryMetadata,
        _: &crate::EntryMetadata,
    ) -> Result<bool, crate::PlatformError> {
        unreachable!()
    }
    fn stream_regular_file_relative(
        &self,
        _: &(),
        _: &RegularFileStreamRequest,
        _: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
    ) -> Result<RegularFileStreamResult, BoundedRegularFileReadError> {
        let mut after = observation(4);
        match self.0 {
            1 => {
                let _ = consume(&[1; 5]);
            }
            2 => {
                consume(&[1; 2])?;
            }
            3 => {
                consume(&[1; 4])?;
                after.change_stamp = RegularFileChangeStamp::new([7]);
            }
            4 => {
                let _ = consume(&[1; 4]);
                let _ = consume(&[]);
            }
            _ => consume(&[1; 4])?,
        }
        Ok(RegularFileStreamResult {
            observed_before: observation(4),
            observed_after: after,
            bytes_read: 4,
        })
    }
}

#[test]
fn wrapper_rejects_bad_backend_results_and_preserves_ignored_consumer_refusal() {
    for mode in 1..=3 {
        assert!(
            stream_bound_regular_file(
                &FaultyBackend(mode),
                &(),
                &request(0, 4, None),
                &CancellationToken::new(),
                &mut |_| Ok(())
            )
            .is_err()
        );
    }
    let refusal = BoundedRegularFileReadError::Unsupported("consumer budget exhausted".into());
    let mut calls = 0;
    assert_eq!(
        stream_bound_regular_file(
            &FaultyBackend(4),
            &(),
            &request(0, 4, None),
            &CancellationToken::new(),
            &mut |_| {
                calls += 1;
                Err(refusal.clone())
            }
        )
        .unwrap_err(),
        refusal
    );
    assert_eq!(calls, 1, "ignored refusal must stop further consumer calls");
    let mut contents = Vec::new();
    assert_eq!(
        stream_bound_regular_file(
            &FaultyBackend(0),
            &(),
            &request(0, 4, None),
            &CancellationToken::new(),
            &mut |chunk| {
                contents.extend_from_slice(chunk);
                Ok(())
            }
        )
        .unwrap()
        .bytes_read,
        4
    );
    assert_eq!(contents, [1; 4]);
}
