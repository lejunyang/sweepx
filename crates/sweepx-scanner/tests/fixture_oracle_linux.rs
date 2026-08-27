#![cfg(all(target_os = "linux", feature = "platform-linux"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sweepx_fixtures::{
    FixtureEntryKind, OracleReport, default_p0_p1_manifest, generate_from_manifest,
    oracle_from_manifest,
};
use sweepx_model::{
    ArithmeticState, DecimalU128, EvidenceValue, IdentityEvidence, ObjectType, ScannedEntry,
};
use sweepx_platform::{BoundaryKind, CancellationToken, ScanRoot};
use sweepx_scanner::{HostPlatformScanner, ScanSummary, Scanner, ScannerOptions};

#[test]
fn deterministic_oracle_matches_linux_host_scanner() {
    let fixture_root = tempfile::tempdir().expect("create fixture root");
    let manifest = default_p0_p1_manifest();
    let generated =
        generate_from_manifest(fixture_root.path(), &manifest).expect("generate fixture");
    let fixture_root = generated
        .fixture_dir
        .parent()
        .expect("generated fixture has a parent");
    let oracle = oracle_from_manifest(fixture_root, &manifest).expect("build independent oracle");

    assert_eq!(generated.receipt, oracle.receipt);

    let summary = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan(
            &[ScanRoot::new(generated.fixture_dir.clone()).expect("absolute fixture root")],
            &CancellationToken::new(),
        )
        .expect("scan generated fixture with the Linux host backend");

    let observed = observed_entries_by_path(&summary);
    assert_eq!(observed.len(), oracle.identities.len());

    for (segments, expected) in &oracle.identities {
        let path = path_from_segments(fixture_root, segments);
        let actual = observed
            .get(&path)
            .unwrap_or_else(|| panic!("scanner omitted oracle entry {}", path.display()));

        assert_eq!(
            actual.object_type,
            scanner_kind(&expected.kind),
            "object kind mismatch for {}",
            path.display()
        );

        // Linux scanner aggregates regular-file bytes. The fixture oracle also records
        // symlink payload length, so only the shared regular-file/directory semantics are
        // compared entry-by-entry.
        if expected.kind != FixtureEntryKind::Symlink {
            assert_eq!(
                actual.logical_bytes,
                expected.logical_bytes,
                "logical byte mismatch for {}",
                path.display()
            );
        }
    }

    assert_symlinks_are_no_follow_boundaries(&summary, &oracle, fixture_root, &observed);
    assert_hardlink_groups_share_linux_identity(&oracle, fixture_root, &observed);

    let root = summary.roots.first().expect("one scanned root");
    assert_eq!(summary.roots.len(), 1);
    let root_id = &root.identity.as_ref().expect("live root identity").entry_id;
    let root_aggregate = summary
        .aggregates
        .iter()
        .find(|aggregate| aggregate.directory_identity == root_id.as_str())
        .expect("root aggregate joins the live root identity");
    let (expected_apparent, expected_unique) = oracle_regular_file_totals(&oracle);

    assert_eq!(
        root_aggregate.apparent_logical_bytes,
        known_bytes(expected_apparent)
    );
    assert_eq!(
        root_aggregate.unique_logical_bytes,
        known_bytes(expected_unique)
    );
    assert!(root_aggregate.coverage.complete);
    assert_eq!(root_aggregate.arithmetic_state, ArithmeticState::Exact);
}

fn observed_entries_by_path(summary: &ScanSummary) -> BTreeMap<PathBuf, &ScannedEntry> {
    let mut observed = BTreeMap::new();
    for entry in summary.roots.iter().chain(&summary.entries) {
        let path = PathBuf::from(&entry.display_path);
        assert!(
            observed.insert(path.clone(), entry).is_none(),
            "scanner emitted duplicate path {}",
            path.display()
        );
    }
    observed
}

fn scanner_kind(kind: &FixtureEntryKind) -> ObjectType {
    match kind {
        FixtureEntryKind::Directory => ObjectType::Directory,
        FixtureEntryKind::File | FixtureEntryKind::Hardlink => ObjectType::File,
        FixtureEntryKind::Symlink => ObjectType::Symlink,
        FixtureEntryKind::Special => ObjectType::Other,
    }
}

fn assert_symlinks_are_no_follow_boundaries(
    summary: &ScanSummary,
    oracle: &OracleReport,
    fixture_root: &Path,
    observed: &BTreeMap<PathBuf, &ScannedEntry>,
) {
    let expected_symlinks = oracle
        .identities
        .iter()
        .filter(|(_, identity)| identity.kind == FixtureEntryKind::Symlink)
        .map(|(segments, _)| path_from_segments(fixture_root, segments))
        .collect::<BTreeSet<_>>();
    assert!(!expected_symlinks.is_empty());

    for (segments, identity) in &oracle.identities {
        if identity.kind != FixtureEntryKind::Symlink {
            continue;
        }
        assert!(identity.link_target.is_some());
        assert!(
            oracle
                .boundaries
                .contains(&format!("kind:{}:symlink", segments.join("/")))
        );
        let path = path_from_segments(fixture_root, segments);
        assert_eq!(
            observed.get(&path).expect("observed symlink").object_type,
            ObjectType::Symlink
        );
    }

    let actual_symlink_boundaries = summary
        .boundaries
        .iter()
        .filter(|boundary| boundary.kind == BoundaryKind::Symlink)
        .map(|boundary| {
            assert_eq!(boundary.reason, sweepx_model::ReasonCode::StrictReadOnly);
            boundary.path.clone()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_symlink_boundaries, expected_symlinks);
    assert_eq!(summary.boundaries.len(), expected_symlinks.len());
}

fn assert_hardlink_groups_share_linux_identity(
    oracle: &OracleReport,
    fixture_root: &Path,
    observed: &BTreeMap<PathBuf, &ScannedEntry>,
) {
    let mut groups = BTreeMap::<&str, Vec<PathBuf>>::new();
    for (segments, identity) in &oracle.identities {
        if let Some(group) = identity.hardlink_group.as_deref() {
            groups
                .entry(group)
                .or_default()
                .push(path_from_segments(fixture_root, segments));
        }
    }
    assert!(!groups.is_empty());

    for (group, paths) in groups {
        assert!(
            paths.len() > 1,
            "oracle hard-link group {group} is not shared"
        );
        let first = &observed[&paths[0]]
            .identity
            .as_ref()
            .expect("live hard-link identity")
            .platform_file_identity;
        assert!(matches!(first, IdentityEvidence::Known { .. }));
        for path in &paths[1..] {
            assert_eq!(
                &observed[path]
                    .identity
                    .as_ref()
                    .expect("live hard-link identity")
                    .platform_file_identity,
                first,
                "hard-link identity mismatch for oracle group {group}"
            );
        }
    }
}

fn oracle_regular_file_totals(oracle: &OracleReport) -> (u128, u128) {
    let mut apparent = 0u128;
    let mut unique = 0u128;
    let mut seen_objects = BTreeSet::new();

    for (segments, identity) in &oracle.identities {
        if !matches!(
            identity.kind,
            FixtureEntryKind::File | FixtureEntryKind::Hardlink
        ) {
            continue;
        }
        let bytes = match identity.logical_bytes {
            EvidenceValue::Known { value } => value.0,
            ref other => panic!(
                "regular fixture file lacks known logical bytes at {}: {other:?}",
                segments.join("/")
            ),
        };
        apparent = apparent.checked_add(bytes).expect("fixture apparent total");
        let object = identity
            .hardlink_group
            .clone()
            .unwrap_or_else(|| format!("entry:{}", segments.join("/")));
        if seen_objects.insert(object) {
            unique = unique.checked_add(bytes).expect("fixture unique total");
        }
    }

    (apparent, unique)
}

fn known_bytes(value: u128) -> sweepx_model::ByteValue {
    EvidenceValue::Known {
        value: DecimalU128::new(value),
    }
}

fn path_from_segments(root: &Path, segments: &[String]) -> PathBuf {
    segments
        .iter()
        .fold(root.to_path_buf(), |path, segment| path.join(segment))
}
