use super::*;
use sweepx_model::{
    Coverage, CoverageState, FieldProvenance, FilesystemObjectDomainIdentity, NativeName,
    PlatformFileIdentity, ReasonCode, ScanEntryId, ScanId, ScanObjectIdentity,
};
use sweepx_platform::{
    EntryIdentity, EntryKind, FilesystemIdentity, MountIdentity, RegularFileChangeStamp,
};

fn file(name: &str, size: usize, inode: u128) -> ScannedEntry {
    let scan = ScanId::new("duplicate-fixture");
    let root = ScanEntryId::for_scan_ordinal(&scan, 1).unwrap();
    ScannedEntry {
        scan_id: scan.clone(),
        display_path: name.into(),
        metadata_fingerprint: name.into(),
        #[cfg(unix)]
        native_basename: NativeName::unix(name.as_bytes().to_vec()),
        #[cfg(windows)]
        native_basename: NativeName::windows_utf16(name.encode_utf16().collect::<Vec<_>>()),
        object_type: ObjectType::File,
        logical_bytes: EvidenceValue::Known {
            value: (size as u128).into(),
        },
        allocated_bytes: EvidenceValue::Unknown {
            reason: ReasonCode::UnknownIdentity,
        },
        reclaimable_estimate: EvidenceValue::NotChecked {
            reason: ReasonCode::NotRevalidated,
        },
        identity: Some(ScanObjectIdentity {
            entry_id: ScanEntryId::for_scan_ordinal(&scan, inode + 2).unwrap(),
            scan_root_id: root.clone(),
            parent_id: Some(root),
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: 7.into(),
                inode: inode.into(),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity { device: 7.into() },
            ),
            volume_or_mount_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
        }),
        native_locator: None,
        coverage: Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: vec![],
            details_lost: false,
            provenance: FieldProvenance::Unknown {
                reason: ReasonCode::Unknown,
            },
        },
        provenance: FieldProvenance::Unknown {
            reason: ReasonCode::Unknown,
        },
    }
}
fn observation(entry: &ScannedEntry) -> RegularFileObservation {
    let IdentityEvidence::Known { value } =
        &entry.identity.as_ref().unwrap().platform_file_identity
    else {
        panic!()
    };
    let EvidenceValue::Known { value: size } = entry.logical_bytes else {
        panic!()
    };
    RegularFileObservation {
        kind: EntryKind::File,
        identity: EntryIdentity::from_windows_file_id(7, value.inode.0.to_le_bytes()),
        filesystem_identity: FilesystemIdentity { device: 7 },
        mount_identity: MountIdentity { value: 99 },
        logical_bytes: size,
        change_stamp: RegularFileChangeStamp::new([1]),
    }
}
#[derive(Default)]
struct Source {
    contents: BTreeMap<String, Vec<u8>>,
    calls: Vec<(String, u64, u64)>,
    fail: Option<(&'static str, bool)>,
    delay: bool,
}
impl DuplicateContentSource for Source {
    fn read(
        &mut self,
        request: FileContentRequest<'_>,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
    ) -> Result<RegularFileStreamResult, FileContentError> {
        self.calls.push((
            request.entry.display_path.clone(),
            request.offset,
            request.max_bytes,
        ));
        if self.delay {
            std::thread::sleep(Duration::from_millis(10));
        }
        if cancel.is_cancelled() {
            return Err(BoundedRegularFileReadError::Cancelled.into());
        }
        if self
            .fail
            .is_some_and(|(name, _)| name == request.entry.display_path)
        {
            if self.fail.unwrap().1 {
                return Err(BoundedRegularFileReadError::ProviderOrOffline(
                    "fixture offline".into(),
                )
                .into());
            }
            return Err(DetailRescanError::IdentityMismatch.into());
        }
        let observed = observation(request.entry);
        if request
            .previous
            .is_some_and(|previous| previous != &observed)
        {
            return Err(DetailRescanError::IdentityMismatch.into());
        }
        let bytes = self.contents.get(&request.entry.display_path).unwrap();
        let range = &bytes[request.offset as usize..(request.offset + request.max_bytes) as usize];
        for chunk in range.chunks(13) {
            consume(chunk)?;
        }
        Ok(RegularFileStreamResult {
            observed_before: observed.clone(),
            observed_after: observed,
            bytes_read: range.len() as u64,
        })
    }
}
fn options() -> DuplicateOptions {
    DuplicateOptions {
        minimum_logical_bytes: 0.into(),
        sample_bytes: 2,
        ..Default::default()
    }
}
fn collect(source: &mut Source, inputs: &[(&str, &[u8], u128)]) -> DuplicateCollector {
    let mut collector = DuplicateCollector::new(options()).unwrap();
    for (name, bytes, inode) in inputs {
        source.contents.insert((*name).into(), bytes.to_vec());
        collector.observe(&file(name, bytes.len(), *inode));
    }
    collector
}

#[test]
fn closed_groups_stream_before_later_io_and_preserve_final_native_stamps() {
    struct Observer {
        cancel: CancellationToken,
        groups: Vec<DuplicateGroup>,
    }
    impl DuplicateAnalysisObserver for Observer {
        fn on_group(&mut self, group: &DuplicateGroup) {
            self.groups.push(group.clone());
            self.cancel.cancel();
        }
    }
    let mut source = Source::default();
    let collector = collect(
        &mut source,
        &[
            ("a", b"abc", 1),
            ("b", b"abc", 2),
            ("c", b"later", 3),
            ("d", b"later", 4),
        ],
    );
    let cancel = CancellationToken::new();
    let mut observer = Observer {
        cancel: cancel.clone(),
        groups: Vec::new(),
    };
    let report = collector.analyze_with_observer(&mut source, true, &cancel, &mut observer);
    assert!(!report.complete);
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::Cancelled)
    );
    assert_eq!(observer.groups, report.groups);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(
        report.groups[0].sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    for (entry, stamp) in report.groups[0]
        .files
        .iter()
        .zip(&report.groups[0].live_observations)
    {
        assert_eq!(stamp, &observation(entry));
    }
    assert!(
        source
            .calls
            .iter()
            .all(|(name, _, _)| name == "a" || name == "b")
    );
}

#[test]
fn provisional_chunks_from_a_failed_read_report_progress_without_publishing_a_group() {
    struct FailedAfterChunks(Source);
    impl DuplicateContentSource for FailedAfterChunks {
        fn read(
            &mut self,
            request: FileContentRequest<'_>,
            cancel: &CancellationToken,
            consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
        ) -> Result<RegularFileStreamResult, FileContentError> {
            self.0.read(request, cancel, consume)?;
            Err(DetailRescanError::IdentityMismatch.into())
        }
    }
    #[derive(Default)]
    struct Observer {
        delivered: u64,
        groups: usize,
    }
    impl DuplicateAnalysisObserver for Observer {
        fn on_read(&mut self, _entry: &ScannedEntry, _charged: u64, delivered: u64) {
            self.delivered = delivered;
        }
        fn on_group(&mut self, _group: &DuplicateGroup) {
            self.groups += 1;
        }
    }
    let mut source = Source::default();
    let collector = collect(&mut source, &[("a", b"abc", 1), ("b", b"abc", 2)]);
    let mut observer = Observer::default();
    let report = collector.analyze_with_observer(
        &mut FailedAfterChunks(source),
        true,
        &CancellationToken::new(),
        &mut observer,
    );
    assert!(observer.delivered > 0);
    assert!(!report.complete);
    assert!(report.groups.is_empty());
    assert_eq!(observer.groups, 0);
}

#[test]
fn full_hash_groups_match_independent_byte_equality_and_exclude_aliases_and_unique_sizes() {
    let mut source = Source::default();
    let inputs: &[(&str, &[u8], u128)] = &[
        ("a", b"abc", 1),
        ("b", b"abc", 2),
        ("alias", b"abc", 1),
        ("c", b"xy-middlex-zz", 3),
        ("d", b"xy-middley-zz", 4),
        ("e", b"single-longer", 5),
        ("unique", b"size unique data", 6),
    ];
    let report = collect(&mut source, inputs).analyze(&mut source, true, &CancellationToken::new());
    assert!(report.complete, "{:?}", report.incomplete_reasons);
    assert_eq!(report.hard_link_aliases_excluded.0, 1);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(
        report.groups[0].sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let names: BTreeSet<_> = report.groups[0]
        .files
        .iter()
        .map(|file| file.display_path.as_str())
        .collect();
    assert_eq!(names, BTreeSet::from(["a", "b"]));
    for group in &report.groups {
        let bytes: BTreeSet<_> = group
            .files
            .iter()
            .map(|file| source.contents[&file.display_path].clone())
            .collect();
        assert_eq!(bytes.len(), 1, "independent full-byte oracle");
        assert!(
            group
                .files
                .iter()
                .all(|file| matches!(file.allocated_bytes, EvidenceValue::Unknown { .. }))
        );
    }
    assert!(
        source
            .calls
            .iter()
            .all(|(name, _, _)| name != "alias" && name != "unique")
    );
    assert!(
        source.calls.iter().any(|(name, offset, count)| name == "c"
            && *offset == 0
            && *count == source.contents["c"].len() as u64),
        "sample collision requires full hash"
    );
}

#[test]
fn same_object_paths_cannot_form_a_group_and_zero_files_can_when_requested() {
    let mut source = Source::default();
    let report = collect(&mut source, &[("a", b"abc", 1), ("alias", b"abc", 1)]).analyze(
        &mut source,
        true,
        &CancellationToken::new(),
    );
    assert!(report.groups.is_empty());
    assert!(source.calls.is_empty());
    assert!(report.complete);
    let mut source = Source::default();
    let report = collect(&mut source, &[("a", b"", 1), ("b", b"", 2)]).analyze(
        &mut source,
        true,
        &CancellationToken::new(),
    );
    assert!(report.complete);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.delivered_bytes.0, 0);
    assert_eq!(
        report.groups[0].sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn budget_counts_failures_and_partial_reports_do_not_infer_uniqueness() {
    let mut source = Source {
        fail: Some(("a", true)),
        ..Default::default()
    };
    let report = collect(&mut source, &[("a", b"abcdefgh", 1), ("b", b"abcdefgh", 2)]).analyze(
        &mut source,
        false,
        &CancellationToken::new(),
    );
    assert!(!report.complete);
    assert!(report.groups.is_empty());
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::ProviderOrOffline)
    );
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::TraversalIncomplete)
    );
    let charged: u128 = source
        .calls
        .iter()
        .map(|(_, _, count)| u128::from(*count))
        .sum();
    assert_eq!(report.read_budget_charged_bytes.0, charged);
    assert!(report.read_budget_charged_bytes.0 > report.delivered_bytes.0);
    let mut source = Source::default();
    let mut collector = collect(&mut source, &[("a", b"abcdefgh", 1), ("b", b"abcdefgh", 2)]);
    collector.options.max_read_bytes = 3;
    let report = collector.analyze(&mut source, true, &CancellationToken::new());
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::ReadLimit)
    );
    assert!(report.read_budget_charged_bytes.0 <= 3);
    assert_eq!(source.calls.len(), 1);
}

#[test]
fn metadata_retention_uncertainty_deadline_and_cancellation_are_distinct_gaps() {
    let mut collector = DuplicateCollector::new(DuplicateOptions {
        max_files: 1,
        ..options()
    })
    .unwrap();
    collector.observe(&file("a", 3, 1));
    collector.observe(&file("b", 3, 2));
    let mut unknown = file("unknown", 3, 3);
    unknown.logical_bytes = EvidenceValue::NotChecked {
        reason: ReasonCode::NotRevalidated,
    };
    collector.observe(&unknown);
    let mut directory = file("dir", 3, 4);
    directory.object_type = ObjectType::Directory;
    collector.observe(&directory);
    let mut source = Source::default();
    let report = collector.analyze(&mut source, true, &CancellationToken::new());
    assert_eq!(report.observed_files.0, 3);
    assert_eq!(
        report.incomplete_reasons,
        vec![
            DuplicateIncompleteReason::MetadataUnavailable,
            DuplicateIncompleteReason::RetentionLimit
        ]
    );
    let mut source = Source {
        delay: true,
        ..Default::default()
    };
    let mut collector = collect(&mut source, &[("a", b"abc", 1), ("b", b"abc", 2)]);
    collector.options.max_duration_ms = 1;
    let report = collector.analyze(&mut source, true, &CancellationToken::new());
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::Deadline)
    );
    assert!(report.groups.is_empty());
    assert_eq!(source.calls.len(), 1, "deadline stops subsequent stages");
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut source = Source::default();
    let collector = collect(&mut source, &[("a", b"abc", 1), ("b", b"abc", 2)]);
    let report = collector.analyze(&mut source, true, &cancel);
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::Cancelled)
    );
    assert!(source.calls.is_empty());
}

#[test]
fn complete_128_bit_ids_keep_distinct_windows_objects_separate() {
    let mut source = Source::default();
    let report = collect(
        &mut source,
        &[("a", b"abc", 1), ("b", b"abc", (1 << 100) + 1)],
    )
    .analyze(&mut source, true, &CancellationToken::new());
    assert!(report.complete);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.hard_link_aliases_excluded.0, 0);
    assert_eq!(report.groups[0].files.len(), 2);
}

#[test]
fn unstable_or_unbound_reads_and_failed_full_hashes_never_form_groups() {
    #[derive(Clone, Copy)]
    enum Fault {
        Identity,
        Length,
        Mount,
        FullRead,
        FinalStamp,
        Oversend,
    }
    struct FaultSource {
        source: Source,
        fault: Fault,
        exercised: bool,
    }
    impl DuplicateContentSource for FaultSource {
        fn read(
            &mut self,
            request: FileContentRequest<'_>,
            cancel: &CancellationToken,
            consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
        ) -> Result<RegularFileStreamResult, FileContentError> {
            let name = request.entry.display_path.as_str();
            let full = request.max_bytes == self.source.contents[name].len() as u64;
            let final_check = request.max_bytes == 0;
            if name == "a" && matches!(self.fault, Fault::FullRead) && full {
                self.exercised = true;
                consume(&self.source.contents[name][..3])?;
                return Err(BoundedRegularFileReadError::io(std::io::Error::other(
                    "mid-read failure",
                ))
                .into());
            }
            if name == "a" && matches!(self.fault, Fault::Oversend) {
                self.exercised = true;
                // Deliberately ignore the consumer's refusal: the analysis must still reject it.
                let _ = consume(&self.source.contents[name]);
            }
            let mut result = self.source.read(request, cancel, consume)?;
            if name == "a" {
                match self.fault {
                    Fault::Identity => {
                        self.exercised = true;
                        result.observed_before.identity = EntryIdentity::from_windows_file_id(
                            7,
                            ((1u128 << 100) + 1).to_le_bytes(),
                        );
                    }
                    Fault::Length => {
                        self.exercised = true;
                        result.observed_before.logical_bytes = 9.into();
                    }
                    Fault::Mount => {
                        self.exercised = true;
                        result.observed_before.mount_identity.value = 101;
                    }
                    Fault::FinalStamp if final_check => {
                        self.exercised = true;
                        result.observed_before.change_stamp = RegularFileChangeStamp::new([2]);
                    }
                    _ => {}
                }
                result.observed_after = result.observed_before.clone();
            }
            Ok(result)
        }
    }
    for fault in [
        Fault::Identity,
        Fault::Length,
        Fault::Mount,
        Fault::FullRead,
        Fault::FinalStamp,
        Fault::Oversend,
    ] {
        let mut source = Source::default();
        let mut collector = collect(&mut source, &[("a", b"abcdefgh", 1), ("b", b"abcdefgh", 2)]);
        if matches!(fault, Fault::Mount) {
            collector.files[0]
                .identity
                .as_mut()
                .unwrap()
                .volume_or_mount_identity =
                IdentityEvidence::known(sweepx_model::VolumeOrMountIdentity { value: 99.into() });
        }
        let mut source = FaultSource {
            source,
            fault,
            exercised: false,
        };
        let report = collector.analyze(&mut source, true, &CancellationToken::new());
        assert!(source.exercised);
        assert!(!report.complete && report.groups.is_empty());
        assert!(report.incomplete_reasons.contains(&if matches!(
            fault,
            Fault::FullRead | Fault::Oversend
        ) {
            DuplicateIncompleteReason::ReadFailed
        } else {
            DuplicateIncompleteReason::ChangedOrUnbound
        }));
        if matches!(fault, Fault::FullRead) {
            assert!(report.delivered_bytes.0 < report.read_budget_charged_bytes.0);
        }
    }
}

#[test]
fn operation_limit_includes_zero_payload_final_validation() {
    let mut source = Source::default();
    let mut collector = collect(&mut source, &[("a", b"abc", 1), ("b", b"abc", 2)]);
    collector.options.max_read_operations = 6; // two samples and a full hash per object
    let report = collector.analyze(&mut source, true, &CancellationToken::new());
    assert!(report.groups.is_empty() && !report.complete);
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::ReadLimit)
    );
    assert_eq!(report.read_operations.0, 6);
    assert_eq!(source.calls.len(), 6);
}

#[test]
fn thresholds_file_byte_limits_and_invalid_options_are_enforced() {
    let mut collector = DuplicateCollector::new(DuplicateOptions {
        minimum_logical_bytes: 3.into(),
        max_file_bytes: 3,
        ..options()
    })
    .unwrap();
    collector.observe(&file("small", 2, 1));
    collector.observe(&file("equal", 3, 2));
    collector.observe(&file("large", 4, 3));
    let report = collector.analyze(&mut Source::default(), true, &CancellationToken::new());
    assert_eq!(report.retained_files.0, 1);
    assert!(
        report
            .incomplete_reasons
            .contains(&DuplicateIncompleteReason::ReadLimit)
    );
    for bad in [
        DuplicateOptions {
            max_files: 0,
            ..options()
        },
        DuplicateOptions {
            max_retained_bytes: 0,
            ..options()
        },
        DuplicateOptions {
            max_read_bytes: 0,
            ..options()
        },
        DuplicateOptions {
            max_duration_ms: 0,
            ..options()
        },
        DuplicateOptions {
            sample_bytes: 0,
            ..options()
        },
    ] {
        assert!(DuplicateCollector::new(bad).is_err());
    }
}
