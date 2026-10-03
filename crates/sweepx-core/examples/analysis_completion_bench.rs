//! Read-only comparison of materialized and completion-only analysis observers.
//! Usage: `analysis_completion_bench legacy|completion large|duplicates ABSOLUTE_ROOT`.
//! Ordinary walk/stat/content oracles and signature export occur outside `coreElapsedNanos`.
//! State is disabled. This measures the core call and result drop, not an interactive TUI.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::Instant};
use sweepx_core::{
    CoreContext, DuplicateGroup, DuplicateOptions, FileAnalysisOptions, FileAnalysisSink,
    LargeFileOptions, LargeFileReport, MemorySnapshotStore, ScanRequest,
    scan_file_analysis_completion_with_observer, scan_file_analysis_with_observer,
};
use sweepx_i18n::{Locale, LocaleResolution, LocaleSource};
use sweepx_model::{EvidenceValue, ScannedEntry};
use sweepx_platform::CancellationToken;
use sweepx_protocol::OutputStatus;

#[derive(Default)]
struct Sink {
    ranking: Option<LargeFileReport>,
    groups: Vec<DuplicateGroup>,
}
impl FileAnalysisSink for Sink {
    fn on_large_files_final(&mut self, report: &LargeFileReport) {
        self.ranking = Some(report.clone());
    }
    fn on_duplicate_group(&mut self, group: &DuplicateGroup) {
        self.groups.push(group.clone());
    }
}

fn walk(root: &Path, files: &mut BTreeMap<String, (u64, String)>) {
    for entry in fs::read_dir(root).expect("oracle directory") {
        let path = entry.expect("oracle entry").path();
        let metadata = fs::symlink_metadata(&path).expect("oracle no-follow metadata");
        if metadata.is_dir() {
            walk(&path, files);
        } else if metadata.is_file() {
            let bytes = fs::read(&path).expect("oracle content");
            assert_eq!(metadata.len(), bytes.len() as u64);
            files.insert(
                path.to_str().expect("UTF-8 fixture").into(),
                (metadata.len(), format!("{:x}", Sha256::digest(bytes))),
            );
        } else {
            panic!("benchmark fixtures must contain only directories and regular files");
        }
    }
}

fn normalize(value: &mut Value) {
    match value {
        Value::Object(map) => {
            // These identifiers are per scan. Validate their native lineage before removing
            // them; keep every native identity, basename, stamp and evidence value unchanged.
            for key in [
                "scan_id",
                "entry_id",
                "parent_id",
                "scan_root_id",
                "observed_at",
            ] {
                map.remove(key);
            }
            for child in map.values_mut() {
                normalize(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                normalize(child);
            }
        }
        _ => {}
    }
}

fn signature(file: &ScannedEntry, oracle: &BTreeMap<String, (u64, String)>) -> Value {
    let expected = oracle
        .get(&file.display_path)
        .expect("file present in oracle");
    assert_eq!(
        file.logical_bytes,
        EvidenceValue::Known {
            value: u128::from(expected.0).into()
        }
    );
    file.native_locator
        .as_ref()
        .expect("live locator")
        .validate_for_identity(
            file.identity.as_ref().expect("live identity"),
            &file.scan_id,
        )
        .expect("current scan and native lineage binding");
    let mut value = serde_json::to_value(file).unwrap();
    normalize(&mut value);
    value
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        4,
        "legacy|completion large|duplicates ABSOLUTE_ROOT"
    );
    let mode = args[1].to_str().unwrap();
    let analysis = args[2].to_str().unwrap();
    let root = Path::new(&args[3]);
    assert!(root.is_absolute());
    let mut oracle = BTreeMap::new();
    walk(root, &mut oracle);
    let large = LargeFileOptions {
        minimum_logical_bytes: 0.into(),
        max_files: 20,
        ..Default::default()
    };
    let duplicates = DuplicateOptions {
        minimum_logical_bytes: 0.into(),
        ..Default::default()
    };
    let options = match analysis {
        "large" => FileAnalysisOptions::Large(&large),
        "duplicates" => FileAnalysisOptions::Duplicates(&duplicates),
        _ => panic!("unknown analysis"),
    };
    let context = CoreContext::new(LocaleResolution::new(Locale::EnUs, LocaleSource::Explicit));
    let request = ScanRequest {
        roots: vec![root.into()],
        state_dir: None,
    };
    let cancel = CancellationToken::new();
    let mut sink = Sink::default();
    let started = Instant::now();
    let status = match mode {
        "legacy" => {
            scan_file_analysis_with_observer::<MemorySnapshotStore>(
                &context, &request, None, options, &cancel, &mut sink,
            )
            .expect("legacy scan")
            .output
            .status
        }
        "completion" => {
            scan_file_analysis_completion_with_observer::<MemorySnapshotStore>(
                &context, &request, None, options, &cancel, &mut sink,
            )
            .expect("completion scan")
            .status
        }
        _ => panic!("unknown mode"),
    };
    let elapsed = started.elapsed();
    assert_eq!(
        status,
        OutputStatus::Ok,
        "partial results are not a timing comparison"
    );
    let facts = if let Some(report) = sink.ranking {
        assert!(report.complete && report.incomplete_reasons.is_empty());
        assert_eq!(report.observed_files.0, oracle.len() as u128);
        let mut expected: Vec<_> = oracle.iter().collect();
        expected.sort_unstable_by_key(|(_, (len, _))| std::cmp::Reverse(*len));
        expected.truncate(large.max_files);
        assert_eq!(report.files.len(), expected.len());
        for (file, (path, _)) in report.files.iter().zip(expected) {
            assert_eq!(
                &file.display_path, path,
                "use fixtures without a top-K size tie"
            );
        }
        let files: Vec<_> = report
            .files
            .iter()
            .map(|file| signature(file, &oracle))
            .collect();
        json!({"observedFiles": report.observed_files, "qualifyingFiles": report.qualifying_files,
            "unknownLogicalFiles": report.unknown_logical_files, "topKLimited": report.top_k_limited,
            "files": files})
    } else {
        let mut expected: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for (path, (len, hash)) in &oracle {
            expected
                .entry((hash.clone(), *len))
                .or_default()
                .push(path.clone());
        }
        expected.retain(|_, paths| paths.len() >= 2);
        let mut actual = BTreeMap::new();
        let mut groups = BTreeMap::new();
        for group in sink.groups {
            assert_eq!(group.files.len(), group.live_observations.len());
            let mut paths = Vec::new();
            let mut files = BTreeMap::new();
            for (file, stamp) in group.files.iter().zip(&group.live_observations) {
                assert_eq!(oracle[&file.display_path].1, group.sha256);
                assert_eq!(stamp.logical_bytes, group.logical_bytes);
                paths.push(file.display_path.clone());
                files.insert(
                    file.display_path.clone(),
                    json!({"file": signature(file, &oracle),
                    "liveStamp": format!("{stamp:?}")}),
                );
            }
            paths.sort();
            actual.insert((group.sha256.clone(), group.logical_bytes.0 as u64), paths);
            groups.insert(group.sha256, files);
        }
        assert_eq!(actual, expected, "ordinary content oracle");
        serde_json::to_value(groups).unwrap()
    };
    println!(
        "{}",
        json!({"mode": mode, "analysis": analysis, "oracleFiles": oracle.len(),
        "coreElapsedNanos": elapsed.as_nanos().to_string(),
        "factsSha256": format!("{:x}", Sha256::digest(serde_json::to_vec(&facts).unwrap()))})
    );
}
