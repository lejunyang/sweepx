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

pub(super) fn fixture() -> (
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
    let project = root.join("nested").join("project");
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

#[test]
fn native_output_scope_selects_sources_bases_and_special_environment_without_authorizing_trash() {
    let (owner, project, mut candidate) = fixture();
    // This fixture validates output selection; declaration-only tests intentionally use a
    // missing member elsewhere. A real standalone package keeps this contract independent.
    std::fs::write(
        project.join("Cargo.toml"),
        b"[package]\nname='output_fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    let nested = project.parent().unwrap();
    let home = owner.path().join("isolated-cargo-home");
    std::fs::create_dir(&home).unwrap();
    #[cfg(unix)]
    let home = home.canonicalize().unwrap();
    std::fs::create_dir(project.join(".cargo")).unwrap();
    std::fs::create_dir(nested.join(".cargo")).unwrap();
    let target = project.join("target");
    let absolute = target.to_str().unwrap();
    let ancestor_target = format!("project{}target", std::path::MAIN_SEPARATOR);
    let home_target = format!("nested{0}project{0}target", std::path::MAIN_SEPARATOR);
    let cases = [
        (
            Some("target"),
            None,
            None,
            None,
            None,
            CargoOutputSource::ProjectConfig,
            CargoOutputPathComparison::SameSpelling,
        ),
        (
            None,
            Some(ancestor_target.as_str()),
            None,
            None,
            None,
            CargoOutputSource::AncestorConfig,
            CargoOutputPathComparison::SameSpelling,
        ),
        (
            None,
            None,
            Some(home_target.as_str()),
            None,
            None,
            CargoOutputSource::CargoHomeConfig,
            CargoOutputPathComparison::SameSpelling,
        ),
        (
            Some("other"),
            None,
            None,
            Some("target"),
            None,
            CargoOutputSource::CargoTargetDir,
            CargoOutputPathComparison::SameSpelling,
        ),
        (
            Some("other"),
            None,
            None,
            None,
            Some("target"),
            CargoOutputSource::CargoBuildTargetDir,
            CargoOutputPathComparison::SameSpelling,
        ),
        (
            Some("target"),
            None,
            None,
            Some("nonexistent-output"),
            Some("target"),
            CargoOutputSource::CargoTargetDir,
            CargoOutputPathComparison::DifferentSpelling,
        ),
        (
            Some(absolute),
            None,
            None,
            None,
            None,
            CargoOutputSource::ProjectConfig,
            CargoOutputPathComparison::SameSpelling,
        ),
        (
            Some("../shared"),
            None,
            None,
            None,
            None,
            CargoOutputSource::ProjectConfig,
            CargoOutputPathComparison::NotChecked,
        ),
        (
            Some("."),
            None,
            None,
            None,
            None,
            CargoOutputSource::ProjectConfig,
            CargoOutputPathComparison::NotChecked,
        ),
    ];
    for (local, ancestor, home_value, target_env, build_env, source, comparison) in cases {
        for (path, value) in [
            (project.join(".cargo/config.toml"), local),
            (nested.join(".cargo/config.toml"), ancestor),
            (home.join("config.toml"), home_value),
        ] {
            if let Some(value) = value {
                let body = format!(
                    "[build]\ntarget-dir={}\n",
                    serde_json::to_string(value).unwrap()
                );
                std::fs::write(path, body).unwrap();
            } else if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }
        let environment = CargoOutputEnvironment::from_values(
            target_env.map(std::ffi::OsStr::new),
            build_env.map(std::ffi::OsStr::new),
            Some(home.as_os_str()),
            None,
        );
        ProjectFormatSession::with_cargo_environment(
            sweepx_scanner::HostPlatformScanner::new(),
            Default::default(),
            CancellationToken::new(),
            environment,
        )
        .refresh(&mut candidate);
        let context = candidate.project_context.unwrap();
        assert_eq!(context.status, ProjectContextStatus::Observed);
        let output = context.cargo_output.unwrap();
        assert_eq!(output.status, ProjectContextStatus::Observed, "{output:?}");
        assert_eq!(output.scope, "project_parent_current_env_no_cli");
        assert!(output.source_locations_observed);
        assert_eq!(output.source, Some(source));
        assert_eq!(output.candidate_path, comparison);
        assert!(!context.cargo_config.unwrap().precedence_complete);
        assert!(candidate.project_execution_blocker().is_some());
        // Ordinary reads are an independent no-mutation oracle; no configured output is created.
        assert_eq!(
            std::fs::read(target.join("personal")).unwrap(),
            b"preserved"
        );
        assert!(!project.join("nonexistent-output").exists());
        assert!(!nested.join("shared").exists());
        let encoded = serde_json::to_string(&output).unwrap();
        assert!(!encoded.contains(absolute));
        assert!(!encoded.contains("nonexistent-output"));
    }
}

#[test]
fn output_scope_keeps_package_defaults_resource_gaps_and_bad_sources_distinct() {
    let (owner, project, mut candidate) = fixture();
    // This fixture validates output selection; declaration-only tests intentionally use a
    // missing member elsewhere. A real standalone package keeps this contract independent.
    std::fs::write(
        project.join("Cargo.toml"),
        b"[package]\nname='output_fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    let home = owner.path().join("isolated-home");
    std::fs::create_dir(&home).unwrap();
    #[cfg(unix)]
    let home = home.canonicalize().unwrap();
    let environment =
        || CargoOutputEnvironment::from_values(None, None, Some(home.as_os_str()), None);
    let refresh = |candidate: &mut crate::junk::candidate::JunkCandidate, limits| {
        ProjectFormatSession::with_cargo_environment(
            sweepx_scanner::HostPlatformScanner::new(),
            limits,
            CancellationToken::new(),
            environment(),
        )
        .refresh(candidate);
        candidate.project_context.unwrap().cargo_output.unwrap()
    };
    let missing = refresh(&mut candidate, Default::default());
    assert!(missing.source_locations_observed, "{missing:?}");
    assert_eq!(missing.status, ProjectContextStatus::Observed);
    assert_eq!(missing.reason, "default_output_observed_non_atomic");
    assert_eq!(missing.source, Some(CargoOutputSource::PackageDefault));
    assert_eq!(
        missing.candidate_path,
        CargoOutputPathComparison::SameSpelling
    );
    let workspace = missing.workspace.unwrap();
    assert!(!workspace.is_workspace);
    assert_eq!(workspace.member_count, 1);
    assert_eq!(workspace.default_member_count, 1);
    let limited = refresh(
        &mut candidate,
        ProjectFormatLimits {
            max_reserved_file_bytes: 3 * 256 * 1024,
            ..Default::default()
        },
    );
    assert_eq!(limited.reason, "resource_limit");
    assert!(!limited.source_locations_observed);
    assert_eq!(
        candidate.project_context.unwrap().status,
        ProjectContextStatus::Observed
    );
    std::fs::write(home.join("config.toml"), b"[build]\ntarget-dir=7").unwrap();
    let invalid = refresh(&mut candidate, Default::default());
    assert_eq!(invalid.reason, "unsupported_manifest_shape");
    std::fs::write(home.join("config.toml"), b"[build").unwrap();
    let invalid = refresh(&mut candidate, Default::default());
    assert_eq!(invalid.status, ProjectContextStatus::Invalid);
    assert_eq!(invalid.reason, "malformed_toml");
    assert!(candidate.project_execution_blocker().is_some());
    assert_eq!(
        std::fs::read(project.join("target/personal")).unwrap(),
        b"preserved"
    );
}

// This recording supplies POSIX HOME semantics; Windows has independently compiled native
// path/absence regressions rather than treating a POSIX run as Windows runtime evidence.
#[cfg(unix)]
#[test]
fn native_home_output_matches_all_pinned_cargo_metadata_observations_without_authority() {
    use std::path::PathBuf;
    let oracle: serde_json::Value =
        serde_json::from_str(sweepx_fixtures::project_junk::CARGO_HOME_ORACLE).unwrap();
    assert_eq!(oracle["complete"], true);
    let records = oracle["records"].as_array().unwrap();
    assert_eq!(records.len(), 17);
    for record in records {
        let (_owner, project, mut candidate) = fixture();
        let root = project.parent().unwrap();
        for directory in record["directories"].as_array().unwrap() {
            std::fs::create_dir_all(root.join(directory.as_str().unwrap())).unwrap();
        }
        let mut originals = Vec::new();
        for input in record["inputs"].as_array().unwrap() {
            let path = root.join(input["path"].as_str().unwrap());
            let bytes = input["utf8"].as_str().unwrap().as_bytes();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            originals.push((path, bytes));
        }
        let home = record["homeValue"].as_str().map(|value| {
            if record["homeKind"] == "absolute" {
                root.join(value)
            } else {
                PathBuf::from(value)
            }
        });
        let fallback = if record["fallbackRelative"] == true {
            PathBuf::from(record["fallbackHome"].as_str().unwrap())
        } else {
            root.join(record["fallbackHome"].as_str().unwrap())
        };
        let environment = CargoOutputEnvironment::from_values(
            None,
            None,
            home.as_deref().map(|path| path.as_os_str()),
            Some(fallback.as_os_str()),
        );
        ProjectFormatSession::with_cargo_environment(
            sweepx_scanner::HostPlatformScanner::new(),
            Default::default(),
            CancellationToken::new(),
            environment,
        )
        .refresh(&mut candidate);
        let output = candidate.project_context.unwrap().cargo_output.unwrap();
        let raw: serde_json::Value =
            serde_json::from_str(record["cargo"]["stdout"].as_str().unwrap()).unwrap();
        assert_eq!(record["cargo"]["status"], 0);
        assert_eq!(record["cargo"]["boundedFailure"], serde_json::Value::Null);
        assert_eq!(record["inputChanges"].as_array().unwrap().len(), 0);
        let raw_target = raw["target_directory"].as_str().unwrap();
        // Relative HOME can make metadata report a relative target. Resolve only against the
        // recorded invocation cwd, preserving its dot components for the spelling contract.
        let relative_target = if let Some(absolute) =
            raw_target.strip_prefix(record["fixtureRoot"].as_str().unwrap())
        {
            absolute.strip_prefix('/').unwrap().to_owned()
        } else {
            assert!(
                !std::path::Path::new(raw_target).is_absolute(),
                "{}",
                record["name"]
            );
            format!(
                "{}/{raw_target}",
                record["fixtureRelativeCwd"].as_str().unwrap()
            )
        };
        let is_default = relative_target == "project/target";
        let comparison = if relative_target
            .split('/')
            .any(|part| matches!(part, "." | ".."))
        {
            CargoOutputPathComparison::NotChecked
        } else if is_default {
            CargoOutputPathComparison::SameSpelling
        } else {
            CargoOutputPathComparison::DifferentSpelling
        };
        assert_eq!(
            output.status,
            ProjectContextStatus::Observed,
            "{}: {output:?}",
            record["name"]
        );
        assert!(output.source_locations_observed);
        assert_eq!(
            output.source,
            Some(if is_default {
                CargoOutputSource::PackageDefault
            } else {
                CargoOutputSource::CargoHomeConfig
            }),
            "{}",
            record["name"]
        );
        assert_eq!(
            output.candidate_path, comparison,
            "{}: {output:?}",
            record["name"]
        );
        assert!(candidate.project_execution_blocker().is_some());
        for (path, bytes) in originals {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        for output_name in [
            "home-output",
            "fallback-output",
            "dot-output",
            "legacy-output",
            "unused-output",
        ] {
            assert!(!root.join(output_name).exists());
            assert!(!project.join(output_name).exists());
        }
        let encoded = serde_json::to_string(&output).unwrap();
        assert!(!encoded.contains(root.to_str().unwrap()));
    }
}

#[test]
fn unavailable_home_environment_never_becomes_absent_configuration() {
    let (_owner, project, mut candidate) = fixture();
    std::fs::write(
        project.join("Cargo.toml"),
        b"[package]\nname='home_fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    for home in [
        None,
        Some(std::ffi::OsStr::new("")),
        Some(std::ffi::OsStr::new("bad\0home")),
    ] {
        ProjectFormatSession::with_cargo_environment(
            sweepx_scanner::HostPlatformScanner::new(),
            Default::default(),
            CancellationToken::new(),
            CargoOutputEnvironment::from_values(None, None, home, None),
        )
        .refresh(&mut candidate);
        let output = candidate.project_context.unwrap().cargo_output.unwrap();
        assert_eq!(output.status, ProjectContextStatus::Unknown, "{output:?}");
        assert!(!output.source_locations_observed);
        assert_eq!(output.source, None);
        assert!(candidate.project_execution_blocker().is_some());
    }
    assert_eq!(
        std::fs::read(project.join("target/personal")).unwrap(),
        b"preserved"
    );
}

#[test]
fn default_workspace_report_counts_packages_and_rejects_missing_members_without_authority() {
    let (owner, project, mut candidate) = fixture();
    let home = owner.path().join("isolated-workspace-home");
    std::fs::create_dir(&home).unwrap();
    #[cfg(unix)]
    let home = home.canonicalize().unwrap();
    std::fs::create_dir(project.join("a")).unwrap();
    std::fs::write(
        project.join("a/Cargo.toml"),
        b"[package]\nname='member'\nversion='0.1.0'\n",
    )
    .unwrap();
    let environment =
        || CargoOutputEnvironment::from_values(None, None, Some(home.as_os_str()), None);
    let refresh = |candidate: &mut crate::junk::candidate::JunkCandidate| {
        ProjectFormatSession::with_cargo_environment(
            sweepx_scanner::HostPlatformScanner::new(),
            Default::default(),
            CancellationToken::new(),
            environment(),
        )
        .refresh(candidate);
        candidate.project_context.unwrap().cargo_output.unwrap()
    };
    let virtual_root = refresh(&mut candidate);
    assert_eq!(
        virtual_root.status,
        ProjectContextStatus::Observed,
        "{virtual_root:?}"
    );
    assert_eq!(
        virtual_root.source,
        Some(CargoOutputSource::WorkspaceDefault)
    );
    assert_eq!(
        virtual_root.candidate_path,
        CargoOutputPathComparison::SameSpelling
    );
    let facts = virtual_root.workspace.unwrap();
    assert!(facts.is_workspace && facts.project_is_root);
    assert_eq!((facts.member_count, facts.default_member_count), (1, 1));
    std::fs::write(
        project.join("Cargo.toml"),
        b"[package]\nname='root_package'\nversion='0.1.0'\n[workspace]\nmembers=['a']\n",
    )
    .unwrap();
    let package_root = refresh(&mut candidate).workspace.unwrap();
    assert!(package_root.is_workspace && package_root.project_is_root);
    assert_eq!(
        (package_root.member_count, package_root.default_member_count),
        (2, 1)
    );
    std::fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    let empty = refresh(&mut candidate).workspace.unwrap();
    assert!(empty.is_workspace);
    assert_eq!((empty.member_count, empty.default_member_count), (0, 0));
    std::fs::write(
        project.join("Cargo.toml"),
        b"[workspace]\nmembers=['missing']\n",
    )
    .unwrap();
    let invalid = refresh(&mut candidate);
    assert_eq!(invalid.status, ProjectContextStatus::Invalid);
    assert_eq!(invalid.reason, "workspace_member_missing");
    assert!(invalid.workspace.is_none());
    assert!(candidate.project_execution_blocker().is_some());
    assert_eq!(
        std::fs::read(project.join("target/personal")).unwrap(),
        b"preserved"
    );
    let encoded = serde_json::to_string(&virtual_root).unwrap();
    assert!(!encoded.contains(project.to_str().unwrap()));
    assert!(!encoded.contains("root_package"));
}
