use super::*;
use crate::junk::{
    JunkService, candidate::refresh_candidate_interpretation, platform::PlatformJunkEvidence,
};
use sweepx_platform::ScanRoot;
use sweepx_scanner::{Scanner, ScannerOptions};

const PUB: &[u8] = br#"{"configVersion":2,"packages":[{"name":"example","rootUri":"../","packageUri":"lib/","languageVersion":"2.18"}],"generator":"pub","generatorVersion":"2.18.0"}"#;

#[test]
fn dart_profile_distinguishes_recognized_invalid_and_unsupported_shapes() {
    assert_eq!(
        inspect_dart_pub_config(PUB).status,
        ProjectFormatStatus::Recognized
    );
    let original: serde_json::Value = serde_json::from_slice(PUB).unwrap();
    for (field, value, status, reason) in [
        (
            "configVersion",
            serde_json::json!(3),
            ProjectFormatStatus::Unknown,
            "unsupported_config_version",
        ),
        (
            "generator",
            serde_json::json!("custom"),
            ProjectFormatStatus::Unknown,
            "pub_generator_not_established",
        ),
        (
            "generatorVersion",
            serde_json::json!("future"),
            ProjectFormatStatus::Unknown,
            "pub_version_not_established",
        ),
        (
            "packages",
            serde_json::json!([]),
            ProjectFormatStatus::Unknown,
            "parent_root_reference_not_established",
        ),
        (
            "packages",
            serde_json::json!(null),
            ProjectFormatStatus::Invalid,
            "invalid_json_or_fields",
        ),
    ] {
        let mut edited = original.clone();
        edited[field] = value;
        let result = inspect_dart_pub_config(&serde_json::to_vec(&edited).unwrap());
        assert_eq!((result.status, result.reason), (status, reason));
    }
    for bytes in [
        b"{}".as_slice(),
        b"{",
        br#"{"configVersion":2,"configVersion":2,"packages":[]}"#,
    ] {
        assert_eq!(
            inspect_dart_pub_config(bytes).status,
            ProjectFormatStatus::Invalid
        );
    }
    let mut duplicate = original.clone();
    duplicate["packages"]
        .as_array_mut()
        .unwrap()
        .push(original["packages"][0].clone());
    assert_eq!(
        inspect_dart_pub_config(&serde_json::to_vec(&duplicate).unwrap()).reason,
        "empty_or_duplicate_package_name"
    );
    let mut workspace = original.clone();
    workspace["generatorVersion"] = serde_json::json!("3.6.0");
    workspace["packages"].as_array_mut().unwrap().push(serde_json::json!({"name":"member", "rootUri":"../packages/member", "packageUri":"lib/", "languageVersion":"3.6"}));
    workspace["unknownExtension"] = serde_json::json!({"retained": false});
    assert_eq!(
        inspect_dart_pub_config(&serde_json::to_vec(&workspace).unwrap()).status,
        ProjectFormatStatus::Recognized
    );
    workspace["packages"][1]["rootUri"] = serde_json::json!("https://example.invalid/member");
    assert_eq!(
        inspect_dart_pub_config(&serde_json::to_vec(&workspace).unwrap()).reason,
        "unsupported_package_uri"
    );
    assert_eq!(
        inspect_dart_pub_config(&vec![b' '; 262145]).status,
        ProjectFormatStatus::Unknown
    );
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, JunkCandidate) {
    #[cfg(target_os = "linux")]
    let owner = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = owner.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    std::fs::create_dir(root.join(".dart_tool")).unwrap();
    std::fs::write(root.join("pubspec.yaml"), "name: example\n").unwrap();
    std::fs::write(root.join(".dart_tool/package_config.json"), PUB).unwrap();
    let summary = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
    let service = JunkService::built_in().unwrap();
    let entry = summary
        .entries
        .iter()
        .find(|e| e.display_path.ends_with(".dart_tool"))
        .unwrap();
    let aggregates = summary
        .aggregates
        .iter()
        .map(|a| (a.directory_identity.as_str(), a))
        .collect();
    let candidate = service
        .interpret(
            "project:dart.tool-state",
            entry,
            &aggregates,
            &[],
            &PlatformJunkEvidence::default(),
        )
        .unwrap();
    (owner, root, candidate)
}

#[test]
fn captured_format_reobserves_body_and_resets_cache_interpretation() {
    let (_owner, root, mut candidate) = fixture();
    assert_eq!(
        candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::NotChecked
    );
    let mut session =
        ProjectFormatSession::new(ProjectFormatLimits::default(), CancellationToken::new());
    // The independent payload comparison also catches accidental edits or package-URI traversal.
    session.refresh(&mut candidate);
    assert_eq!(
        candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Recognized
    );
    assert_eq!(
        std::fs::read(root.join(".dart_tool/package_config.json")).unwrap(),
        PUB
    );
    assert_eq!(
        candidate.project_execution_blocker(),
        Some("project_ownership_not_verified")
    );
    assert_eq!(candidate.confidence.as_deref(), Some("medium"));
    // Same directory, filename and length; current contents must not inherit a cached answer.
    std::fs::write(
        root.join(".dart_tool/package_config.json"),
        vec![b'x'; PUB.len()],
    )
    .unwrap();
    let service = JunkService::built_in().unwrap();
    candidate = refresh_candidate_interpretation(
        candidate,
        service.project_rules(),
        &[],
        &PlatformJunkEvidence::default(),
    )
    .unwrap();
    assert_eq!(
        candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::NotChecked
    );
    let mut next =
        ProjectFormatSession::new(ProjectFormatLimits::default(), CancellationToken::new());
    next.refresh(&mut candidate);
    assert_eq!(
        candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Invalid
    );
    let mut git =
        crate::junk::git::GitEvidenceSession::new(Default::default(), CancellationToken::new());
    git.refresh(std::slice::from_mut(&mut candidate));
    assert_eq!(candidate.classification.as_deref(), Some("project_layout"));
    assert_eq!(candidate.confidence.as_deref(), Some("low"));
    assert!(
        candidate
            .blockers
            .iter()
            .any(|b| b == "project_format_invalid")
    );
    assert!(candidate.project_execution_blocker().is_some());
}

#[test]
fn captured_format_bounds_and_cancellation_never_mean_invalid_or_absent() {
    let (_owner, root, candidate) = fixture();
    for limits in [
        ProjectFormatLimits {
            max_observations: 0,
            ..Default::default()
        },
        ProjectFormatLimits {
            max_reserved_file_bytes: 1,
            ..Default::default()
        },
        ProjectFormatLimits {
            max_file_bytes: 8,
            ..Default::default()
        },
        ProjectFormatLimits {
            timeout: Duration::ZERO,
            ..Default::default()
        },
    ] {
        let mut row = candidate.clone();
        ProjectFormatSession::new(limits, CancellationToken::new()).refresh(&mut row);
        assert_eq!(
            row.project_format.as_ref().unwrap().status,
            ProjectFormatStatus::Unknown
        );
        assert!(row.project_execution_blocker().is_some());
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut row = candidate.clone();
    ProjectFormatSession::new(Default::default(), cancel).refresh(&mut row);
    assert_eq!(row.project_format.unwrap().reason, "cancelled");
    std::fs::remove_file(root.join(".dart_tool/package_config.json")).unwrap();
    let mut row = candidate;
    ProjectFormatSession::new(Default::default(), CancellationToken::new()).refresh(&mut row);
    assert_eq!(
        row.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Unknown
    );
}

struct CountingBackend {
    inner: HostPlatformScanner,
    reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    provider_failure: bool,
}
impl PlatformScanner for CountingBackend {
    type DirectoryHandle = <HostPlatformScanner as PlatformScanner>::DirectoryHandle;
    fn platform_name(&self) -> &'static str {
        self.inner.platform_name()
    }
    fn admit_root(
        &self,
        root: &sweepx_platform::ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<sweepx_platform::RootAdmission<Self::DirectoryHandle>, sweepx_platform::PlatformError>
    {
        self.inner.admit_root(root, cancel)
    }
    fn enumerate_children(
        &self,
        directory: &mut Self::DirectoryHandle,
        cancel: &CancellationToken,
        limits: sweepx_platform::DirectoryReadLimits,
    ) -> Result<sweepx_platform::DirectoryEntryBatch, sweepx_platform::PlatformError> {
        self.inner.enumerate_children(directory, cancel, limits)
    }
    fn inspect_child(
        &self,
        parent: &Self::DirectoryHandle,
        child: &sweepx_platform::DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<sweepx_platform::WalkEntry<Self::DirectoryHandle>, sweepx_platform::PlatformError>
    {
        self.inner.inspect_child(parent, child, cancel)
    }
    fn inspect_child_with_directory_admission(
        &self,
        parent: &Self::DirectoryHandle,
        child: &sweepx_platform::DirectoryEntryRecord,
        cancel: &CancellationToken,
        admission: sweepx_platform::DirectoryHandleAdmission,
    ) -> Result<sweepx_platform::WalkEntry<Self::DirectoryHandle>, sweepx_platform::PlatformError>
    {
        self.inner
            .inspect_child_with_directory_admission(parent, child, cancel, admission)
    }
    fn is_same_mount(
        &self,
        root: &sweepx_platform::EntryMetadata,
        entry: &sweepx_platform::EntryMetadata,
    ) -> Result<bool, sweepx_platform::PlatformError> {
        self.inner.is_same_mount(root, entry)
    }
    fn stream_regular_file_relative(
        &self,
        parent: &Self::DirectoryHandle,
        request: &sweepx_platform::RegularFileStreamRequest,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), sweepx_platform::BoundedRegularFileReadError>,
    ) -> Result<
        sweepx_platform::RegularFileStreamResult,
        sweepx_platform::BoundedRegularFileReadError,
    > {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.provider_failure {
            return Err(
                sweepx_platform::BoundedRegularFileReadError::ProviderOrOffline(
                    "controlled provider refusal".into(),
                ),
            );
        }
        self.inner
            .stream_regular_file_relative(parent, request, cancel, consume)
    }
}

#[test]
fn provider_failure_and_reserved_work_are_bounded_and_deduplicated() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (_owner, _root, original) = fixture();
    for provider_failure in [false, true] {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut observer = ProjectFormatSession::with_platform(
            CountingBackend {
                inner: HostPlatformScanner::new(),
                reads: reads.clone(),
                provider_failure,
            },
            ProjectFormatLimits {
                max_observations: 1,
                ..Default::default()
            },
            CancellationToken::new(),
        );
        let mut row = original.clone();
        observer.refresh(&mut row);
        assert_eq!(
            row.project_format.as_ref().unwrap().status,
            if provider_failure {
                ProjectFormatStatus::Unknown
            } else {
                ProjectFormatStatus::Recognized
            }
        );
        if provider_failure {
            assert_eq!(
                row.project_format.as_ref().unwrap().reason,
                "provider_or_offline"
            );
        }
        let count = reads.load(Ordering::SeqCst);
        assert_eq!(count, if provider_failure { 1 } else { 2 });
        observer.refresh(&mut row);
        assert_eq!(reads.load(Ordering::SeqCst), count);
        // A different captured scan ID cannot evade an exhausted attempt reservation.
        row.entry_id =
            ScanEntryId::for_scan_ordinal(&sweepx_model::ScanId::new("different"), 1).unwrap();
        observer.refresh(&mut row);
        assert_eq!(
            row.project_format.as_ref().unwrap().reason,
            "resource_limit"
        );
        assert_eq!(reads.load(Ordering::SeqCst), count);
        row.entry_id = ScanEntryId::from_loaded("x".repeat(1025));
        observer.refresh(&mut row);
        assert_eq!(
            row.project_format.as_ref().unwrap().reason,
            "resource_limit"
        );
        assert_eq!(reads.load(Ordering::SeqCst), count);
    }
}

#[test]
#[cfg(unix)]
fn linked_config_is_unknown_without_reading_external_payload() {
    let (_owner, root, mut row) = fixture();
    let file = root.join(".dart_tool/package_config.json");
    std::fs::remove_file(&file).unwrap();
    let external = root.join("source-config.json");
    std::fs::write(&external, PUB).unwrap();
    std::os::unix::fs::symlink(&external, &file).unwrap();
    ProjectFormatSession::new(Default::default(), CancellationToken::new()).refresh(&mut row);
    assert_eq!(
        row.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Unknown
    );
    assert_eq!(row.project_format.as_ref().unwrap().reason, "linked_file");
    assert_eq!(std::fs::read(&external).unwrap(), PUB);
}

#[test]
#[cfg(target_os = "macos")]
fn filesystem_cache_omits_content_answers_and_reconstructs_current_requirements() {
    let (_owner, root, mut candidate) = fixture();
    ProjectFormatSession::new(Default::default(), CancellationToken::new()).refresh(&mut candidate);
    assert_eq!(
        candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Recognized
    );
    let stored = crate::junk::cache::StoredJunkCandidate::from_candidate(&candidate);
    let json = serde_json::to_value(&stored).unwrap();
    assert!(json.get("projectFormat").is_none());
    assert!(json.get("project_format").is_none());
    let stored: crate::junk::cache::StoredJunkCandidate = serde_json::from_value(json).unwrap();
    std::fs::write(
        root.join(".dart_tool/package_config.json"),
        vec![b'x'; PUB.len()],
    )
    .unwrap();
    let restored = stored.into_candidate();
    assert!(restored.project_format.is_none());
    let service = JunkService::built_in().unwrap();
    let mut rebuilt = refresh_candidate_interpretation(
        restored,
        service.project_rules(),
        &[],
        &PlatformJunkEvidence::default(),
    )
    .unwrap();
    assert_eq!(
        rebuilt.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::NotChecked
    );
    assert!(rebuilt.project_execution_blocker().is_some());
    ProjectFormatSession::new(Default::default(), CancellationToken::new()).refresh(&mut rebuilt);
    assert_eq!(
        rebuilt.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Invalid
    );
}

#[test]
fn excessive_json_depth_is_resource_unknown_instead_of_malformed() {
    let mut bytes = br#"{"configVersion":2,"packages":[],"extension":"#.to_vec();
    bytes.extend(std::iter::repeat_n(b'[', 140));
    bytes.push(b'0');
    bytes.extend(std::iter::repeat_n(b']', 140));
    bytes.push(b'}');
    let evidence = inspect_dart_pub_config(&bytes);
    assert_eq!(
        (evidence.status, evidence.reason),
        (ProjectFormatStatus::Unknown, "resource_limit")
    );
}

#[test]
fn dependency_file_uri_signatures_recognize_unix_and_windows_without_opening_them() {
    for uri in [
        "file:///home/example/pub-cache/package",
        "file:///C:/Users/example/pub-cache/package",
    ] {
        let mut config: serde_json::Value = serde_json::from_slice(PUB).unwrap();
        config["packages"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "name":"dependency", "rootUri":uri, "packageUri":"lib/",
            }));
        assert_eq!(
            inspect_dart_pub_config(&serde_json::to_vec(&config).unwrap()).status,
            ProjectFormatStatus::Recognized
        );
    }
}

#[test]
fn json_depth_admission_ignores_brackets_and_escapes_inside_strings() {
    let mut config: serde_json::Value = serde_json::from_slice(PUB).unwrap();
    config["extension"] = serde_json::json!(format!("{}\\\"{}", "[".repeat(150), "}".repeat(150)));
    assert_eq!(
        inspect_dart_pub_config(&serde_json::to_vec(&config).unwrap()).status,
        ProjectFormatStatus::Recognized
    );
}
