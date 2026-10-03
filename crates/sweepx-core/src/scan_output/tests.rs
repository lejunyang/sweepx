use super::*;
use std::fs;

fn context(locale: Locale) -> CoreContext {
    CoreContext::new(LocaleResolution::new(
        locale,
        sweepx_i18n::LocaleSource::Explicit,
    ))
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    // Content analysis needs a supported local filesystem rather than an arbitrary /tmp mount.
    #[cfg(target_os = "linux")]
    let fixture = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fixture.path().canonicalize().unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    for index in 0..80 {
        fs::write(
            root.join(format!("file-{index:03}-百分比%")),
            vec![b'x'; index + 1],
        )
        .unwrap();
    }
    (fixture, root)
}

fn legacy(root: &Path) -> ScanSuccess {
    scan_with_store::<MemorySnapshotStore>(
        &context(Locale::EnUs),
        &ScanRequest {
            roots: vec![root.into()],
            state_dir: None,
        },
        None,
    )
    .unwrap()
}

fn small_output(scan: ScanSuccess) -> ScanOutput {
    let mut scan = scan;
    scan.output.data = json!({});
    ScanOutput::new(scan)
}

#[test]
fn streamed_machine_envelope_preserves_every_legacy_fact_and_native_encoding() {
    let (_fixture, root) = fixture();
    let scan = legacy(&root);
    // Independent metadata oracle: names/order come from the ordinary host directory API.
    let expected = fs::read_dir(&root)
        .unwrap()
        .map(|item| {
            let item = item.unwrap();
            (
                item.path().display().to_string(),
                item.metadata().unwrap().len(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let actual = scan
        .summary
        .entries
        .iter()
        .filter(|entry| entry.object_type == ObjectType::File)
        .map(|entry| {
            (
                entry.display_path.clone(),
                match entry.logical_bytes {
                    EvidenceValue::Known { value } => u64::try_from(value.0).unwrap(),
                    ref evidence => panic!("missing logical bytes: {evidence:?}"),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual, expected);
    assert!(
        scan.summary
            .entries
            .iter()
            .all(|entry| entry.native_locator.is_some())
    );
    let expected = serde_json::to_value(&scan.output).unwrap();
    let output = small_output(scan);
    let mut bytes = Vec::new();
    output.write_json(&mut bytes).unwrap();
    let actual: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(actual, expected);
    let _: OutputEnvelope = serde_json::from_slice(&bytes).unwrap();
    assert!(output.metadata.data.as_object().unwrap().is_empty());
}

#[test]
fn bounded_human_selection_matches_full_sort_for_evidence_and_locales() {
    let (_fixture, root) = fixture();
    let mut scan = legacy(&root);
    for (index, entry) in scan.summary.entries.iter_mut().enumerate() {
        entry.reclaimable_estimate = match index % 6 {
            0 => EvidenceValue::Known {
                value: DecimalU128::new(0),
            },
            1 => EvidenceValue::Known {
                value: DecimalU128::new(u128::MAX - index as u128),
            },
            2 => EvidenceValue::LowerBound {
                value: DecimalU128::new(index as u128),
                reason: ReasonCode::ResourceLimit,
            },
            3 => EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            4 => EvidenceValue::Unsupported {
                reason: ReasonCode::UnsupportedPlatform,
            },
            _ => EvidenceValue::NotChecked {
                reason: ReasonCode::NotRevalidated,
            },
        };
    }
    // Duplicate display paths retain root-first precedence. Aggregates still override rows.
    scan.summary.entries.push(scan.summary.roots[0].clone());
    scan.output.data["entries"] =
        camelize_json_keys(serde_json::to_value(&scan.summary.entries).unwrap());
    let expected = scan.output.clone();
    let output = small_output(scan);
    for locale in [Locale::EnUs, Locale::ZhCn] {
        for unit in [
            HumanSizeUnit::Auto,
            HumanSizeUnit::Bytes,
            HumanSizeUnit::GiB,
        ] {
            for sort in [ScanSort::Size, ScanSort::Path] {
                let context = context(locale);
                assert_eq!(
                    output.render_human(&context, unit, sort),
                    render_human_output_with_size_unit(&context, &expected, unit, sort)
                );
            }
        }
    }
    assert!(select_rows(&output.summary, ScanSort::Size, 40).rows.len() <= 40);
}

#[test]
fn output_seam_preserves_cancelled_terminal_evidence() {
    let (_fixture, root) = fixture();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let output = scan_for_output_with_store::<MemorySnapshotStore>(
        &context(Locale::EnUs),
        &ScanRequest {
            roots: vec![root],
            state_dir: None,
        },
        None,
        None,
        &cancel,
    )
    .unwrap();
    assert_eq!(output.metadata.status, OutputStatus::Cancelled);
    let mut bytes = Vec::new();
    output.write_json(&mut bytes).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["status"], "cancelled");
    assert_eq!(
        value["data"]["boundaries"].as_array().unwrap().len(),
        output.summary.boundaries.len()
    );
}

#[test]
fn partial_rows_and_independent_ranking_survive_incremental_export() {
    let (_fixture, root) = fixture();
    let cancel = CancellationToken::new();
    let options = LargeFileOptions {
        minimum_logical_bytes: 0.into(),
        max_files: 3,
        ..Default::default()
    };
    let result = scan_with_store_options(
        &context(Locale::EnUs),
        &ScanRequest {
            roots: vec![root.clone()],
            state_dir: None,
        },
        Option::<&MemorySnapshotStore>::None,
        ScannerOptions {
            resource_limits: sweepx_platform::ScanResourceLimits {
                max_retained_entries: 1,
                max_progress_events: 0,
                ..Default::default()
            },
            ..Default::default()
        },
        None,
        None,
        None,
        Some(large_files::FileAnalysisObservation {
            options: FileAnalysisOptions::Large(&options),
            cancel: &cancel,
            sink: None,
        }),
        ScanProjection::Borrowed(&cancel),
    )
    .unwrap();
    let output = ScanOutput::new(result.scan);
    assert_eq!(output.metadata.status, OutputStatus::Partial);
    assert_eq!(output.summary.entries.len(), 1);
    assert!(output.metadata.data.get("entries").is_none());
    let mut bytes = Vec::new();
    output.write_json(&mut bytes).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["data"]["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        value["data"]["boundaries"].as_array().unwrap().len(),
        output.summary.boundaries.len()
    );
    assert_eq!(
        value["warnings"],
        serde_json::to_value(&output.metadata.warnings).unwrap()
    );
    assert_eq!(
        value["data"]["largeFiles"],
        output.metadata.data["largeFiles"]
    );
    let actual = value["data"]["largeFiles"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| {
            file["logicalBytes"]["value"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let mut expected = fs::read_dir(root)
        .unwrap()
        .map(|file| file.unwrap().metadata().unwrap().len())
        .collect::<Vec<_>>();
    expected.sort_unstable_by(|left, right| right.cmp(left));
    expected.truncate(3);
    assert_eq!(actual, expected);
}

#[test]
fn duplicate_analysis_report_uses_the_same_machine_envelope() {
    let (_fixture, root) = fixture();
    fs::write(root.join("copy-a"), b"identical content").unwrap();
    fs::write(root.join("copy-b"), b"identical content").unwrap();
    let options = DuplicateOptions {
        minimum_logical_bytes: 0.into(),
        ..Default::default()
    };
    let output = scan_for_output_with_store::<MemorySnapshotStore>(
        &context(Locale::EnUs),
        &ScanRequest {
            roots: vec![root],
            state_dir: None,
        },
        None,
        Some(FileAnalysisOptions::Duplicates(&options)),
        &CancellationToken::new(),
    )
    .unwrap();
    let mut bytes = Vec::new();
    output.write_json(&mut bytes).unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["data"]["duplicates"],
        output.metadata.data["duplicates"]
    );
    assert_eq!(
        value["data"]["duplicates"]["groups"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        value["data"]["duplicates"]["groups"][0]["files"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn writer_failure_stops_before_projecting_later_rows() {
    struct Counted<'a>(&'a std::cell::Cell<usize>);
    impl Serialize for Counted<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.set(self.0.get() + 1);
            serializer.serialize_str("row")
        }
    }
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let projected = std::cell::Cell::new(0);
    let rows = [Counted(&projected), Counted(&projected)];
    let error = serde_json::to_writer(Closed, &Rows(&rows)).unwrap_err();
    assert_eq!(error.io_error_kind(), Some(std::io::ErrorKind::BrokenPipe));
    assert_eq!(projected.get(), 0);
    struct Limited(usize);
    impl Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let written = bytes.len().min(self.0);
            self.0 -= written;
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let rows = (0..16).map(|_| Counted(&projected)).collect::<Vec<_>>();
    let error = serde_json::to_writer(Limited(10), &Rows(&rows)).unwrap_err();
    assert_eq!(error.io_error_kind(), Some(std::io::ErrorKind::BrokenPipe));
    // A mid-document failure can project the current row, but never all remaining rows.
    assert_eq!(projected.get(), 2);
    let (_fixture, root) = fixture();
    let output = small_output(legacy(&root));
    assert_eq!(
        output.write_json(Closed).unwrap_err().io_error_kind(),
        Some(std::io::ErrorKind::BrokenPipe)
    );
}
