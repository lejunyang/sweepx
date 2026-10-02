use super::*;
use crate::junk::{
    JunkService,
    candidate::refresh_candidate_interpretation,
    format::{ProjectFormatLimits, ProjectFormatSession},
    platform::PlatformJunkEvidence,
};
use sweepx_platform::CancellationToken;

#[test]
fn declarations_distinguish_patterns_explicit_workspace_and_missing_members() {
    let evidence = inspect_cargo_manifest_context(
        r#"
[workspace]
members = ["crates/*", "外部成员"]
exclude = ["crates/private"]
default-members = []
[workspace.dependencies]
shared = { path = "../shared" }
"#
        .as_bytes(),
    );
    assert_eq!(evidence.status, ProjectContextStatus::Observed);
    let declarations = evidence.cargo_manifest.unwrap();
    assert_eq!(
        declarations.kind,
        CargoManifestDeclarationKind::VirtualWorkspace
    );
    assert_eq!(declarations.member_patterns, Some(2));
    assert_eq!(declarations.exclude_patterns, Some(1));
    assert_eq!(declarations.default_member_patterns, Some(0));
    assert!(declarations.path_dependencies_declared);
    assert!(!declarations.explicit_workspace);
    let encoded = serde_json::to_string(&evidence).unwrap();
    for private in ["crates/*", "外部成员", "../shared", "crates/private"] {
        assert!(!encoded.contains(private));
    }
    let package = inspect_cargo_manifest_context(b"[package]\nname='member'\nworkspace='../'\n")
        .cargo_manifest
        .unwrap();
    assert_eq!(package.kind, CargoManifestDeclarationKind::Package);
    assert!(package.explicit_workspace);
    assert_eq!(package.member_patterns, None);
    let empty = inspect_cargo_manifest_context(b"[workspace]\nmembers=[]\n")
        .cargo_manifest
        .unwrap();
    assert_eq!(empty.member_patterns, Some(0));
}

#[test]
fn invalid_and_unsupported_context_never_produces_declarations() {
    for (bytes, status) in [
        (
            &b"[workspace]\nmembers=["[..],
            ProjectContextStatus::Invalid,
        ),
        (
            &b"[workspace]\nmembers=[]\nmembers=[]\n"[..],
            ProjectContextStatus::Invalid,
        ),
        (&b"\xff"[..], ProjectContextStatus::Invalid),
        (
            &b"[workspace]\nmembers=[7]\n"[..],
            ProjectContextStatus::Unknown,
        ),
        (&b"[package]\nname=''\n"[..], ProjectContextStatus::Unknown),
        (
            &b"[package]\nname='a'\nworkspace='../'\n[workspace]\n"[..],
            ProjectContextStatus::Unknown,
        ),
        (&b""[..], ProjectContextStatus::Unknown),
    ] {
        let evidence = inspect_cargo_manifest_context(bytes);
        assert_eq!(evidence.status, status);
        assert!(evidence.cargo_manifest.is_none());
    }
}

fn fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    crate::junk::candidate::JunkCandidate,
) {
    #[cfg(target_os = "linux")]
    let owner = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = owner.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    let project = root.join("nested/project");
    std::fs::create_dir_all(project.join("target")).unwrap();
    std::fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=['a']\n").unwrap();
    std::fs::write(project.join("target/personal"), b"preserved").unwrap();
    let service = JunkService::built_in().unwrap();
    let context = crate::CoreContext::new(sweepx_i18n::LocaleResolution::new(
        sweepx_i18n::Locale::EnUs,
        sweepx_i18n::LocaleSource::Explicit,
    ));
    let scan = crate::scan_junk_with_store::<crate::MemorySnapshotStore>(
        &context,
        &crate::ScanRequest {
            roots: vec![root],
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
        .map(|a| (a.directory_identity.as_str(), a))
        .collect();
    let entry = scan
        .scan
        .summary
        .entries
        .iter()
        .find(|e| e.display_path.ends_with("target"))
        .unwrap();
    let candidate = service
        .interpret(
            scan.decisions
                .get(&entry.identity.as_ref().unwrap().entry_id)
                .unwrap(),
            entry,
            &aggregates,
            &[],
            &PlatformJunkEvidence::default(),
        )
        .unwrap();
    (owner, project, candidate)
}

#[test]
fn native_context_reobserves_each_invocation_without_granting_project_trash() {
    let (_owner, project, mut candidate) = fixture();
    assert_eq!(
        candidate.project_context.unwrap().status,
        ProjectContextStatus::NotChecked
    );
    let mut session = ProjectFormatSession::new(Default::default(), CancellationToken::new());
    session.refresh(&mut candidate);
    let first = candidate.project_context.unwrap();
    assert_eq!(first.status, ProjectContextStatus::Observed);
    assert_eq!(first.cargo_manifest.unwrap().member_patterns, Some(1));
    assert!(candidate.project_execution_blocker().is_some());
    let before = std::fs::read(project.join("Cargo.toml")).unwrap();
    let changed = b"[workspace]\nexclude=['a']\n";
    assert_eq!(before.len(), changed.len());
    std::fs::write(project.join("Cargo.toml"), changed).unwrap();
    session.refresh(&mut candidate);
    assert_eq!(candidate.project_context.unwrap(), first); // Invocation-only deduplication.
    let service = JunkService::built_in().unwrap();
    let mut refreshed = refresh_candidate_interpretation(
        candidate.clone(),
        service.project_rules(),
        &[],
        &PlatformJunkEvidence::default(),
    )
    .unwrap();
    assert_eq!(
        refreshed.project_context.unwrap().status,
        ProjectContextStatus::NotChecked
    );
    ProjectFormatSession::new(Default::default(), CancellationToken::new()).refresh(&mut refreshed);
    let current = refreshed.project_context.unwrap();
    assert_eq!(current.status, ProjectContextStatus::Observed);
    assert_eq!(current.cargo_manifest.unwrap().member_patterns, None);
    assert_eq!(current.cargo_manifest.unwrap().exclude_patterns, Some(1));
    assert!(refreshed.project_execution_blocker().is_some());
    let mut forged = refreshed.clone();
    forged.execution_policy =
        crate::junk::candidate::JunkExecutionPolicy::NativeRevalidationRequired;
    forged.blockers.clear();
    forged.confidence = Some("high".into());
    assert_eq!(
        forged.project_execution_blocker(),
        Some("project_ownership_not_verified")
    );
    assert_eq!(std::fs::read(project.join("Cargo.toml")).unwrap(), changed);
    assert_eq!(
        std::fs::read(project.join("target/personal")).unwrap(),
        b"preserved"
    );
    #[cfg(target_os = "macos")]
    {
        let stored = crate::junk::cache::StoredJunkCandidate::from_candidate(&refreshed);
        let value = serde_json::to_value(&stored).unwrap();
        assert!(value.get("projectContext").is_none());
        assert!(value.get("project_context").is_none());
        let restored = stored.into_candidate();
        assert!(restored.project_context.is_none());
        assert!(restored.project_execution_blocker().is_some());
    }
}

#[test]
fn context_failures_stay_visible_and_do_not_reuse_a_successful_answer() {
    let (_owner, project, candidate) = fixture();
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
            max_file_bytes: 1,
            ..Default::default()
        },
    ] {
        let mut row = candidate.clone();
        ProjectFormatSession::new(limits, CancellationToken::new()).refresh(&mut row);
        assert_eq!(row.project_context.unwrap().reason, "resource_limit");
        assert!(row.project_execution_blocker().is_some());
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut row = candidate.clone();
    ProjectFormatSession::new(Default::default(), cancel).refresh(&mut row);
    assert_eq!(row.project_context.unwrap().reason, "cancelled");
    std::fs::rename(project.join("target"), project.join("original-target")).unwrap();
    std::fs::create_dir(project.join("target")).unwrap();
    ProjectFormatSession::new(Default::default(), CancellationToken::new()).refresh(&mut row);
    assert_eq!(
        row.project_context.unwrap().reason,
        "identity_changed_or_missing"
    );
    assert!(row.project_execution_blocker().is_some());
    assert_eq!(
        std::fs::read(project.join("original-target/personal")).unwrap(),
        b"preserved"
    );
}

#[test]
fn content_and_context_share_one_invocation_budget() {
    use crate::junk::format::{ProjectFormatEvidence, ProjectFormatStatus};
    use sweepx_catalog::junk::ProjectContentFormat;
    let (_owner, _project, mut candidate) = fixture();
    candidate.project_format = Some(ProjectFormatEvidence::not_checked(
        ProjectContentFormat::DartPubPackageConfigV2,
    ));
    ProjectFormatSession::new(
        ProjectFormatLimits {
            max_observations: 1,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .refresh(&mut candidate);
    assert_eq!(
        candidate.project_context.unwrap().status,
        ProjectContextStatus::Observed
    );
    let format = candidate.project_format.as_ref().unwrap();
    assert_eq!(format.status, ProjectFormatStatus::Unknown);
    assert_eq!(format.reason, "resource_limit");
    assert!(candidate.project_execution_blocker().is_some());
}

#[test]
fn config_declarations_share_the_cleaner_decoder_without_retaining_paths() {
    for (bytes, declared) in [
        (&b"[build]\ntarget-dir='secret/location'\n"[..], Some(true)),
        (&b"[build]\njobs=2\n"[..], Some(false)),
        (&b"[build]\ntarget-dir='../shared'\n"[..], Some(true)),
        (
            &b"[build]\ntarget-dir='/private/absolute'\n"[..],
            Some(true),
        ),
        (&b"include=['private.toml']\n"[..], None),
        (&b"[build]\ntarget-dir=7\n"[..], None),
        (&b"[build]\ntarget-dir='x'\ntarget-dir='y'\n"[..], None),
        (&b"\xff"[..], None),
    ] {
        let evidence = inspect_cargo_target_dir_declaration(bytes);
        assert_eq!(evidence.declared, declared);
        assert_eq!(
            evidence.status == ProjectContextStatus::Observed,
            declared.is_some()
        );
        let json = serde_json::to_string(&evidence).unwrap();
        for private in [
            "secret/location",
            "../shared",
            "/private/absolute",
            "private.toml",
        ] {
            assert!(!json.contains(private));
        }
    }
}

#[test]
fn native_config_observations_refresh_and_preserve_ambiguity_and_execution_guards() {
    let (_owner, project, mut candidate) = fixture();
    let cargo = project.join(".cargo");
    std::fs::create_dir(&cargo).unwrap();
    std::fs::write(
        cargo.join("config"),
        b"[build]\ntarget-dir='private/legacy'\n",
    )
    .unwrap();
    std::fs::write(
        cargo.join("config.toml"),
        b"[build]\ntarget-dir='private/modern'\n",
    )
    .unwrap();
    let mut session = ProjectFormatSession::new(Default::default(), CancellationToken::new());
    session.refresh(&mut candidate);
    let config = candidate.project_context.unwrap().cargo_config.unwrap();
    assert_eq!(config.config.declared, Some(true));
    assert_eq!(config.config_toml.declared, Some(true));
    assert_eq!(config.consistency, CargoConfigConsistency::NonAtomic);
    assert!(!config.precedence_complete);
    assert!(candidate.project_execution_blocker().is_some());
    let json = serde_json::to_string(&config).unwrap();
    assert!(!json.contains("private/legacy"));
    assert!(!json.contains("private/modern"));
    std::fs::write(cargo.join("config"), b"[build]\njobs=2\n").unwrap();
    std::fs::remove_file(cargo.join("config.toml")).unwrap();
    session.refresh(&mut candidate);
    assert_eq!(
        candidate.project_context.unwrap().cargo_config.unwrap(),
        config
    );
    ProjectFormatSession::new(Default::default(), CancellationToken::new()).refresh(&mut candidate);
    let current = candidate.project_context.unwrap().cargo_config.unwrap();
    assert_eq!(current.config.declared, Some(false));
    assert_eq!(current.config_toml.declared, None);
    assert_eq!(current.config_toml.reason, "config_not_observed_non_atomic");
    assert!(!current.precedence_complete);
    assert_eq!(
        std::fs::read(cargo.join("config")).unwrap(),
        b"[build]\njobs=2\n"
    );
    assert_eq!(
        std::fs::read(project.join("target/personal")).unwrap(),
        b"preserved"
    );
    assert!(candidate.project_execution_blocker().is_some());
    let mut limited = candidate.clone();
    ProjectFormatSession::new(
        ProjectFormatLimits {
            max_reserved_file_bytes: 2 * 256 * 1024,
            ..Default::default()
        },
        CancellationToken::new(),
    )
    .refresh(&mut limited);
    assert_eq!(limited.project_context.unwrap().reason, "resource_limit");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("config", cargo.join("config.toml")).unwrap();
        ProjectFormatSession::new(Default::default(), CancellationToken::new())
            .refresh(&mut candidate);
        let current = candidate.project_context.unwrap();
        assert_eq!(current.status, ProjectContextStatus::Observed);
        assert_eq!(current.cargo_config.unwrap().config.declared, None);
        assert!(candidate.project_execution_blocker().is_some());
    }
}

#[test]
fn target_path_kinds_are_host_lexical_and_never_expand_or_normalize_values() {
    let mut cases = vec![
        ("../shared", CargoTargetDirPathKind::ParentRelative),
        ("output/../shared", CargoTargetDirPathKind::ParentRelative),
        (".", CargoTargetDirPathKind::Relative),
        ("./output", CargoTargetDirPathKind::Relative),
        ("~/literal", CargoTargetDirPathKind::Relative),
        ("$OUTPUT/literal", CargoTargetDirPathKind::Relative),
        ("目录/缓存", CargoTargetDirPathKind::Relative),
    ];
    #[cfg(unix)]
    cases.extend([
        ("/private/absolute", CargoTargetDirPathKind::Absolute),
        (r"C:\output", CargoTargetDirPathKind::Relative),
        (r"..\shared", CargoTargetDirPathKind::Relative),
    ]);
    #[cfg(windows)]
    cases.extend([
        (r"C:\output", CargoTargetDirPathKind::Absolute),
        (r"\\server\share\output", CargoTargetDirPathKind::Absolute),
        (r"C:output", CargoTargetDirPathKind::DriveRelative),
        (r"\output", CargoTargetDirPathKind::RootRelative),
        (r"..\shared", CargoTargetDirPathKind::ParentRelative),
    ]);
    for (value, kind) in cases {
        let body = format!(
            "[build]\ntarget-dir={}\n",
            serde_json::to_string(value).unwrap()
        );
        let evidence = inspect_cargo_target_dir_declaration(body.as_bytes());
        assert_eq!(evidence.status, ProjectContextStatus::Observed, "{value}");
        assert_eq!(evidence.declared, Some(true));
        assert_eq!(evidence.path_kind, Some(kind), "{value}");
        let json = serde_json::to_value(evidence).unwrap();
        assert_eq!(json["pathKind"], kind.code());
        assert!(json.get("value").is_none());
    }
    let absent = inspect_cargo_target_dir_declaration(b"[build]\njobs=2\n");
    assert_eq!(absent.declared, Some(false));
    assert_eq!(absent.path_kind, None);
    for (body, reason) in [
        (
            "[build]\ntarget-dir=''".to_string(),
            "invalid_target_dir_declaration",
        ),
        (
            r#"[build]
target-dir="\u0000"
"#
            .to_string(),
            "invalid_target_dir_declaration",
        ),
        (
            format!("[build]\ntarget-dir='{}'", "x".repeat(4097)),
            "resource_limit",
        ),
    ] {
        let evidence = inspect_cargo_target_dir_declaration(body.as_bytes());
        assert_eq!(evidence.status, ProjectContextStatus::Unknown);
        assert_eq!(evidence.reason, reason);
        assert_eq!(evidence.declared, None);
        assert_eq!(evidence.path_kind, None);
    }
}

#[test]
fn native_target_path_declarations_are_reobserved_without_opening_declared_outputs() {
    let (owner, project, mut candidate) = fixture();
    let cargo = project.join(".cargo");
    std::fs::create_dir(&cargo).unwrap();
    let never_created = owner.path().join("no-output-directory");
    let absolute = never_created.to_str().unwrap();
    for (value, kind) in [
        ("../shared", CargoTargetDirPathKind::ParentRelative),
        (absolute, CargoTargetDirPathKind::Absolute),
        (".", CargoTargetDirPathKind::Relative),
        ("~/literal", CargoTargetDirPathKind::Relative),
    ] {
        let body = format!(
            "[build]\ntarget-dir={}\n",
            serde_json::to_string(value).unwrap()
        );
        std::fs::write(cargo.join("config.toml"), &body).unwrap();
        ProjectFormatSession::new(Default::default(), CancellationToken::new())
            .refresh(&mut candidate);
        let evidence = candidate.project_context.unwrap().cargo_config.unwrap();
        assert_eq!(evidence.config_toml.declared, Some(true));
        assert_eq!(evidence.config_toml.path_kind, Some(kind));
        assert!(!evidence.precedence_complete);
        assert!(candidate.project_execution_blocker().is_some());
        // Ordinary reads independently verify the config and user payload remain intact.
        assert_eq!(
            std::fs::read(cargo.join("config.toml")).unwrap(),
            body.as_bytes()
        );
        assert_eq!(
            std::fs::read(project.join("target/personal")).unwrap(),
            b"preserved"
        );
        assert!(!never_created.exists());
        let report = serde_json::to_string(&evidence).unwrap();
        if value.len() > 1 {
            assert!(
                !report.contains(value),
                "raw target declaration leaked: {value}"
            );
        }
    }
}
