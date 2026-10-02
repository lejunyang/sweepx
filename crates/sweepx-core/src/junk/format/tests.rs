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
    action: Option<(usize, StreamAction)>,
}
enum StreamAction {
    FailProvider,
    Mutate(std::path::PathBuf, Vec<u8>),
    Cancel,
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
        let number = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.provider_failure
            || matches!(&self.action, Some((at, StreamAction::FailProvider)) if *at == number)
        {
            return Err(
                sweepx_platform::BoundedRegularFileReadError::ProviderOrOffline(
                    "controlled provider refusal".into(),
                ),
            );
        }
        let result = self
            .inner
            .stream_regular_file_relative(parent, request, cancel, consume)?;
        if let Some((at, action)) = &self.action
            && *at == number
        {
            match action {
                StreamAction::Mutate(path, bytes) => std::fs::write(path, bytes).unwrap(),
                StreamAction::Cancel => cancel.cancel(),
                StreamAction::FailProvider => unreachable!(),
            }
        }
        Ok(result)
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
                action: None,
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

use sweepx_fixtures::project_junk::{SVELTEKIT_AMBIENT, SVELTEKIT1_CONFIG, SVELTEKIT2_CONFIG};

fn recorded_file<'a>(
    recording: &'a sweepx_fixtures::project_junk::recordings::SvelteKitRecording,
    name: &str,
) -> &'a [u8] {
    recording
        .files
        .iter()
        .find(|file| file.recording_name == name)
        .unwrap()
        .bytes
}

#[test]
fn executed_legacy_sdk_outputs_match_without_rewriting_generated_bytes() {
    for recording in sweepx_fixtures::project_junk::recordings::SVELTEKIT {
        let config = recorded_file(recording, "generated-tsconfig.json");
        let ambient = recorded_file(recording, "ambient.d.ts");
        let evidence = inspect_sveltekit_sync(config, ambient);
        assert_eq!(evidence.status, ProjectFormatStatus::Recognized);
        assert_eq!(
            evidence.reason,
            match recording.version {
                "1.0.0" => "sveltekit_legacy_node_non_atomic_signatures",
                "2.0.0" => "sveltekit_legacy_bundler_non_atomic_signatures",
                _ => panic!("add an independently verified expectation for this recorded version"),
            }
        );
        // A valid JSON document/real generator header alone cannot admit custom output. Keep
        // these explicit counterexamples alongside, rather than normalizing them into positives.
        let mut custom: serde_json::Value = serde_json::from_slice(config).unwrap();
        custom["compilerOptions"]["rootDirs"] = serde_json::json!(["../../personal", "./types"]);
        assert_eq!(
            inspect_sveltekit_sync(&serde_json::to_vec(&custom).unwrap(), ambient).reason,
            "unsupported_sync_config_shape"
        );
    }
}

#[test]
fn recorded_sdk_project_with_personal_payload_remains_report_only_and_reobserves_cache() {
    for recording in sweepx_fixtures::project_junk::recordings::SVELTEKIT {
        #[cfg(target_os = "linux")]
        let owner = tempfile::tempdir_in("/dev/shm").unwrap();
        #[cfg(not(target_os = "linux"))]
        let owner = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = owner.path().canonicalize().unwrap();
        #[cfg(windows)]
        let root = owner.path().to_path_buf();
        for file in recording.files {
            let path = root.join(file.project_path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, file.bytes).unwrap();
        }
        std::fs::write(
            root.join(".svelte-kit/personal-notes"),
            b"keep these user notes",
        )
        .unwrap();
        let service = JunkService::built_in().unwrap();
        let context = crate::CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let scan = crate::scan_junk_with_store::<crate::MemorySnapshotStore>(
            &context,
            &crate::ScanRequest {
                roots: vec![root.clone()],
                state_dir: None,
            },
            None,
            &service,
            None,
        )
        .unwrap();
        let aggregates = scan
            .scan
            .summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect();
        let mut candidates = scan
            .scan
            .summary
            .entries
            .iter()
            .filter_map(|entry| {
                let identity = entry.identity.as_ref()?;
                service.interpret(
                    scan.decisions.get(&identity.entry_id)?,
                    entry,
                    &aggregates,
                    &[],
                    &PlatformJunkEvidence::default(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 1);
        let candidate = &mut candidates[0];
        assert_eq!(candidate.rule_id, "node.sveltekit-output");
        ProjectFormatSession::new(ProjectFormatLimits::default(), CancellationToken::new())
            .refresh(candidate);
        assert_eq!(
            candidate.project_format.as_ref().unwrap().status,
            ProjectFormatStatus::Recognized
        );
        assert_eq!(
            candidate.project_execution_blocker(),
            Some("project_ownership_not_verified")
        );
        // Verify all real generated/source bytes through ordinary filesystem reads. Adding user
        // data does not invalidate generated signatures and therefore cannot establish ownership.
        for file in recording.files {
            assert_eq!(
                std::fs::read(root.join(file.project_path)).unwrap(),
                file.bytes
            );
        }
        assert_eq!(
            std::fs::read(root.join(".svelte-kit/personal-notes")).unwrap(),
            b"keep these user notes"
        );
        #[cfg(target_os = "macos")]
        {
            let stored = crate::junk::cache::StoredJunkCandidate::from_candidate(candidate);
            let serialized = serde_json::to_value(&stored).unwrap();
            assert!(serialized.get("projectFormat").is_none());
            assert!(serialized.get("project_format").is_none());
            let mut restored = refresh_candidate_interpretation(
                stored.into_candidate(),
                service.project_rules(),
                &[],
                &PlatformJunkEvidence::default(),
            )
            .unwrap();
            assert_eq!(
                restored.project_format.as_ref().unwrap().status,
                ProjectFormatStatus::NotChecked
            );
            let mut edited: serde_json::Value =
                serde_json::from_slice(recorded_file(recording, "generated-tsconfig.json"))
                    .unwrap();
            edited["compilerOptions"]["moduleResolution"] = serde_json::json!("custom");
            std::fs::write(
                root.join(".svelte-kit/tsconfig.json"),
                serde_json::to_vec(&edited).unwrap(),
            )
            .unwrap();
            ProjectFormatSession::new(ProjectFormatLimits::default(), CancellationToken::new())
                .refresh(&mut restored);
            assert_eq!(
                restored.project_format.as_ref().unwrap().status,
                ProjectFormatStatus::Unknown
            );
            assert_eq!(
                restored.project_execution_blocker(),
                Some("project_ownership_not_verified")
            );
            assert_eq!(
                std::fs::read(root.join(".svelte-kit/personal-notes")).unwrap(),
                b"keep these user notes"
            );
        }
    }
}

#[test]
fn legacy_sync_profiles_distinguish_real_signatures_from_user_and_changed_shapes() {
    for config in [SVELTEKIT1_CONFIG, SVELTEKIT2_CONFIG] {
        let result = inspect_sveltekit_sync(config.as_bytes(), SVELTEKIT_AMBIENT.as_bytes());
        assert_eq!(result.status, ProjectFormatStatus::Recognized);
        assert!(result.reason.contains("non_atomic"));
        let mut edited: serde_json::Value = serde_json::from_str(config).unwrap();
        edited["compilerOptions"]["rootDirs"] = serde_json::json!(["../../outside", "./types"]);
        assert_eq!(
            inspect_sveltekit_sync(
                &serde_json::to_vec(&edited).unwrap(),
                SVELTEKIT_AMBIENT.as_bytes()
            )
            .status,
            ProjectFormatStatus::Unknown
        );
        edited["compilerOptions"]["rootDirs"] = serde_json::json!(true);
        assert_eq!(
            inspect_sveltekit_sync(
                &serde_json::to_vec(&edited).unwrap(),
                SVELTEKIT_AMBIENT.as_bytes()
            )
            .status,
            ProjectFormatStatus::Invalid
        );
    }
    for ambient in [
        "/// <reference types=\"@sveltejs/kit\" />",
        "user source",
        "\n// this file is generated — do not edit it\n",
    ] {
        assert_eq!(
            inspect_sveltekit_sync(SVELTEKIT2_CONFIG.as_bytes(), ambient.as_bytes()).status,
            ProjectFormatStatus::Unknown
        );
    }
    let changed = SVELTEKIT_AMBIENT.replace("$env/dynamic/private", "$env/dynamic/other");
    assert_eq!(
        inspect_sveltekit_sync(SVELTEKIT2_CONFIG.as_bytes(), changed.as_bytes()).reason,
        "ambient_signature_not_established"
    );
    assert_eq!(
        inspect_sveltekit_sync(SVELTEKIT2_CONFIG.as_bytes(), &[0xff]).status,
        ProjectFormatStatus::Invalid
    );
    assert_eq!(
        inspect_sveltekit_sync(
            br#"{"compilerOptions":{},"compilerOptions":{}}"#,
            SVELTEKIT_AMBIENT.as_bytes()
        )
        .status,
        ProjectFormatStatus::Invalid
    );
    assert_eq!(
        inspect_sveltekit_sync(
            br#"{"compilerOptions":{},"include":[]}"#,
            SVELTEKIT_AMBIENT.as_bytes()
        )
        .status,
        ProjectFormatStatus::Unknown
    );
    let windows = SVELTEKIT_AMBIENT.replace('\n', "\r\n");
    assert_eq!(
        inspect_sveltekit_sync(SVELTEKIT2_CONFIG.as_bytes(), windows.as_bytes()).status,
        ProjectFormatStatus::Recognized
    );
    assert_eq!(
        inspect_sveltekit_sync(SVELTEKIT2_CONFIG.as_bytes(), &vec![b'x'; 262145]).reason,
        "resource_limit"
    );
}

fn svelte_fixture() -> (tempfile::TempDir, std::path::PathBuf, JunkCandidate) {
    let (owner, root, _dart) = fixture();
    std::fs::create_dir(root.join(".svelte-kit")).unwrap();
    std::fs::write(root.join("svelte.config.js"), "export default {}\n").unwrap();
    std::fs::write(root.join(".svelte-kit/tsconfig.json"), SVELTEKIT2_CONFIG).unwrap();
    std::fs::write(root.join(".svelte-kit/ambient.d.ts"), SVELTEKIT_AMBIENT).unwrap();
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
        .find(|e| e.display_path.ends_with(".svelte-kit"))
        .unwrap();
    let aggregates = summary
        .aggregates
        .iter()
        .map(|a| (a.directory_identity.as_str(), a))
        .collect();
    let candidate = service
        .interpret(
            "project:node.sveltekit-output",
            entry,
            &aggregates,
            &[],
            &PlatformJunkEvidence::default(),
        )
        .unwrap();
    (owner, root, candidate)
}

#[test]
fn svelte_native_pair_is_reobserved_budgeted_and_deduplicated_without_display_paths() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (_owner, root, mut row) = svelte_fixture();
    row.path = "/fabricated/display/path".into();
    row.source_entry.as_mut().unwrap().display_path = "/fabricated/source/display".into();
    let reads = Arc::new(AtomicUsize::new(0));
    let mut session = ProjectFormatSession::with_platform(
        CountingBackend {
            inner: HostPlatformScanner::new(),
            reads: reads.clone(),
            provider_failure: false,
            action: None,
        },
        ProjectFormatLimits {
            max_reserved_file_bytes: 1048576,
            ..Default::default()
        },
        CancellationToken::new(),
    );
    session.refresh(&mut row);
    assert_eq!(
        row.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Recognized
    );
    assert_eq!(reads.load(Ordering::SeqCst), 8); // zero-probe + full read, twice per file
    assert!(row.project_execution_blocker().is_some());
    session.refresh(&mut row);
    assert_eq!(reads.load(Ordering::SeqCst), 8);
    row.entry_id = ScanEntryId::for_scan_ordinal(&sweepx_model::ScanId::new("next"), 1).unwrap();
    session.refresh(&mut row);
    assert_eq!(
        row.project_format.as_ref().unwrap().reason,
        "resource_limit"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 8);
    assert_eq!(
        std::fs::read(root.join(".svelte-kit/tsconfig.json")).unwrap(),
        SVELTEKIT2_CONFIG.as_bytes()
    );
    assert_eq!(
        std::fs::read(root.join(".svelte-kit/ambient.d.ts")).unwrap(),
        SVELTEKIT_AMBIENT.as_bytes()
    );
}

#[test]
fn svelte_interfile_changes_provider_refusal_cancel_and_small_budget_stay_unknown() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    for (action, reason, expected_reads) in [
        (StreamAction::FailProvider, "provider_or_offline", 3),
        (StreamAction::Cancel, "cancelled", 3),
    ] {
        let (_owner, _root, mut row) = svelte_fixture();
        let reads = Arc::new(AtomicUsize::new(0));
        let mut session = ProjectFormatSession::with_platform(
            CountingBackend {
                inner: HostPlatformScanner::new(),
                reads: reads.clone(),
                provider_failure: false,
                action: Some((2, action)),
            },
            Default::default(),
            CancellationToken::new(),
        );
        session.refresh(&mut row);
        assert_eq!(
            row.project_format.as_ref().unwrap().status,
            ProjectFormatStatus::Unknown
        );
        assert_eq!(row.project_format.as_ref().unwrap().reason, reason);
        assert_eq!(reads.load(Ordering::SeqCst), expected_reads);
    }
    let (_owner, root, mut row) = svelte_fixture();
    let reads = Arc::new(AtomicUsize::new(0));
    let mut changed = ProjectFormatSession::with_platform(
        CountingBackend {
            inner: HostPlatformScanner::new(),
            reads: reads.clone(),
            provider_failure: false,
            action: Some((
                3,
                StreamAction::Mutate(
                    root.join(".svelte-kit/tsconfig.json"),
                    SVELTEKIT1_CONFIG.as_bytes().to_vec(),
                ),
            )),
        },
        Default::default(),
        CancellationToken::new(),
    );
    changed.refresh(&mut row);
    assert_eq!(
        row.project_format.as_ref().unwrap().reason,
        "content_changed_between_reads"
    );
    assert_eq!(
        row.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Unknown
    );
    assert_eq!(reads.load(Ordering::SeqCst), 6);
    let reads = Arc::new(AtomicUsize::new(0));
    let mut bounded = ProjectFormatSession::with_platform(
        CountingBackend {
            inner: HostPlatformScanner::new(),
            reads: reads.clone(),
            provider_failure: false,
            action: None,
        },
        ProjectFormatLimits {
            max_reserved_file_bytes: 1048575,
            ..Default::default()
        },
        CancellationToken::new(),
    );
    bounded.refresh(&mut row);
    assert_eq!(
        row.project_format.as_ref().unwrap().reason,
        "resource_limit"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 0);
}
