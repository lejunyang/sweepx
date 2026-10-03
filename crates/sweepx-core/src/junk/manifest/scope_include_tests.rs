use super::config_native::ConfigInputs;
use super::*;
use crate::junk::format::{ProjectFormatLimits, ProjectFormatSession};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use sweepx_platform::CancellationToken;
use sweepx_scanner::{
    HostPlatformScanner, LocatorDirectoryIdentity, LocatorReadLimits, LocatorReader,
};
#[cfg(unix)]
use sweepx_scanner::{Scanner, ScannerOptions};

#[cfg(unix)]
#[test]
fn native_include_graph_and_output_scope_match_all_raw_cargo_observations() {
    use std::ffi::OsStr;
    let raw: serde_json::Value =
        serde_json::from_str(sweepx_fixtures::project_junk::CARGO_INCLUDE_ORACLE).unwrap();
    assert_eq!(raw["complete"], true);
    let records = raw["records"].as_array().unwrap();
    assert_eq!(records.len(), 64);
    let mut successes = 0;
    let mut rejections = 0;
    for record in records {
        let (_owner, project, mut candidate) = super::tests::fixture();
        let root = project.parent().unwrap();
        let recorded_root = record["fixtureRoot"].as_str().unwrap();
        let mut originals = Vec::new();
        for input in record["inputs"].as_array().unwrap() {
            let path = root.join(input["path"].as_str().unwrap());
            let body = input["utf8"]
                .as_str()
                .unwrap()
                .replace(recorded_root, root.to_str().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &body).unwrap();
            originals.push((path, body));
        }
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let special = record["environment"]["CARGO_TARGET_DIR"].as_str();
        let generic = record["environment"]["CARGO_BUILD_TARGET_DIR"].as_str();
        ProjectFormatSession::with_cargo_environment(
            HostPlatformScanner::new(),
            Default::default(),
            CancellationToken::new(),
            CargoOutputEnvironment::from_values(
                special.map(OsStr::new),
                generic.map(OsStr::new),
                Some(home.as_os_str()),
                None,
            ),
        )
        .refresh(&mut candidate);
        let output = candidate.project_context.unwrap().cargo_output.unwrap();
        assert_eq!(output.config_model, "cargo_1_98");
        assert!(record["cargo"]["boundedFailure"].is_null());
        assert!(record["inputChanges"].as_array().unwrap().is_empty());
        if record["cargo"]["status"] == 0 {
            successes += 1;
            let metadata: serde_json::Value =
                serde_json::from_str(record["cargo"]["stdout"].as_str().unwrap()).unwrap();
            let expected = PathBuf::from(
                metadata["target_directory"]
                    .as_str()
                    .unwrap()
                    .replace(recorded_root, root.to_str().unwrap()),
            );
            assert_eq!(
                output.status,
                ProjectContextStatus::Observed,
                "{} {output:?}",
                record["name"]
            );
            assert!(output.source_locations_observed);
            assert_eq!(
                output.candidate_path,
                if expected == project.join("target") {
                    CargoOutputPathComparison::SameSpelling
                } else {
                    CargoOutputPathComparison::DifferentSpelling
                },
                "{}",
                record["name"]
            );

            // A mere "different spelling" would also accept a wrong included value/base. Create
            // Cargo's independently reported directory only in this fixture, scan its actual
            // native row, and compare the graph's defining-file base/value against that row.
            // Production never opens or creates a configured output directory.
            if special.is_none() && generic.is_none() {
                std::fs::create_dir_all(&expected).unwrap();
                let scan = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
                    .scan(
                        &[sweepx_platform::ScanRoot::new(root.to_path_buf()).unwrap()],
                        &CancellationToken::new(),
                    )
                    .unwrap();
                let entry = scan
                    .entries
                    .iter()
                    .find(|entry| entry.display_path == expected.to_str().unwrap())
                    .unwrap();
                let reader = LocatorReader::new(HostPlatformScanner::new(), input_limits());
                let cancel = CancellationToken::new();
                let project_id = reader
                    .capture_directory_identity(&project, &cancel)
                    .unwrap();
                let ancestor_id = reader.capture_directory_identity(root, &cancel).unwrap();
                let home_id = reader.capture_directory_identity(&home, &cancel).unwrap();
                let mut reserved = 0;
                let mut budget = ScopeBudget {
                    reserved_bytes: &mut reserved,
                    max_reserved_bytes: 32 * 1024 * 1024,
                    file_bytes: 256 * 1024,
                    started: Instant::now(),
                    timeout: Duration::from_secs(5),
                };
                let mut inputs = ConfigInputs::default();
                inputs.begin();
                let mut selected = None;
                for (id, nested, base) in [
                    (&project_id, true, project_id.clone()),
                    (&ancestor_id, true, ancestor_id.clone()),
                    (
                        &home_id,
                        false,
                        reader
                            .capture_parent_directory(&home_id, &cancel)
                            .unwrap()
                            .unwrap(),
                    ),
                ] {
                    let target = inputs
                        .source(&reader, id, nested, None, &cancel, &mut budget)
                        .unwrap_or_else(|reason| panic!("{}: {reason}", record["name"]));
                    if selected.is_none()
                        && let Some(target) = target
                    {
                        selected = Some((target, base));
                    }
                }
                if let Some((target, base)) = selected {
                    let base = target.include_base.unwrap_or(base);
                    assert!(
                        reader
                            .compare_scanned_directory_to_configured_path(
                                entry,
                                &base,
                                Path::new(&target.value),
                                &cancel
                            )
                            .unwrap(),
                        "{}: graph does not match Cargo output",
                        record["name"]
                    );
                } else {
                    assert_eq!(expected, project.join("target"));
                }
                inputs.finish(&reader, &cancel, &mut budget).unwrap();
            }
        } else {
            rejections += 1;
            assert_eq!(record["cargo"]["status"], 101);
            assert_ne!(
                output.status,
                ProjectContextStatus::Observed,
                "{} {output:?}",
                record["name"]
            );
            assert!(!output.source_locations_observed);
            assert_eq!(output.source, None);
        }
        assert!(candidate.project_execution_blocker().is_some());
        for (path, body) in originals {
            assert_eq!(std::fs::read(path).unwrap(), body.as_bytes());
        }
        assert!(
            !serde_json::to_string(&output)
                .unwrap()
                .contains(root.to_str().unwrap())
        );
    }
    assert_eq!((successes, rejections), (35, 29));
}

fn source_fixture(
    config: &str,
    file: Option<&str>,
) -> (
    tempfile::TempDir,
    PathBuf,
    ConfigInputs,
    LocatorReader<HostPlatformScanner>,
    LocatorDirectoryIdentity,
) {
    let (owner, project, _) = super::tests::fixture();
    std::fs::create_dir(project.join(".cargo")).unwrap();
    std::fs::write(project.join(".cargo/config.toml"), config).unwrap();
    if let Some(file) = file {
        std::fs::write(project.join(".cargo/input.toml"), file).unwrap();
    }
    let reader = LocatorReader::new(HostPlatformScanner::new(), input_limits());
    let directory = reader
        .capture_directory_identity(&project, &CancellationToken::new())
        .unwrap();
    (owner, project, ConfigInputs::default(), reader, directory)
}

fn input_limits() -> LocatorReadLimits {
    LocatorReadLimits {
        max_requests: 64,
        max_components_per_request: 64,
        max_total_components: 129,
        max_file_bytes: 256 * 1024,
        max_total_bytes: 512 * 1024,
        ..Default::default()
    }
}

#[test]
fn include_inputs_are_revalidated_after_parsing_and_optional_absence_is_not_sealed() {
    for mode in [
        "content",
        "replacement",
        "missing_file",
        "missing_parent",
        "root_content",
    ] {
        let config = if mode == "missing_parent" {
            "include=[{path='missing/input.toml',optional=true}]\n"
        } else if mode == "missing_file" {
            "include=[{path='input.toml',optional=true}]\n"
        } else {
            "include=['input.toml']\n"
        };
        let file = (!mode.starts_with("missing")).then_some("[build]\ntarget-dir='output'\n");
        let (_owner, project, mut inputs, reader, directory) = source_fixture(config, file);
        let cancel = CancellationToken::new();
        let mut reserved = 0;
        let mut budget = ScopeBudget {
            reserved_bytes: &mut reserved,
            max_reserved_bytes: 32 * 1024 * 1024,
            file_bytes: 256 * 1024,
            started: Instant::now(),
            timeout: Duration::from_secs(5),
        };
        inputs.begin();
        inputs
            .source(&reader, &directory, true, None, &cancel, &mut budget)
            .unwrap();
        let included = project.join(".cargo/input.toml");
        match mode {
            "content" => std::fs::write(&included, "[build]\ntarget-dir='another'\n").unwrap(),
            "replacement" => {
                std::fs::rename(&included, included.with_extension("retained")).unwrap();
                std::fs::write(&included, file.unwrap()).unwrap();
            }
            "missing_file" => std::fs::write(&included, "[build]\n").unwrap(),
            "missing_parent" => {
                std::fs::create_dir(project.join(".cargo/missing")).unwrap();
                std::fs::write(project.join(".cargo/missing/input.toml"), "[build]\n").unwrap();
            }
            "root_content" => std::fs::write(
                project.join(".cargo/config.toml"),
                "include=['input.toml']\n[build]\njobs=1\n",
            )
            .unwrap(),
            _ => unreachable!(),
        }
        assert!(
            inputs.finish(&reader, &cancel, &mut budget).is_err(),
            "{mode}"
        );
    }
}

#[test]
fn include_limits_cancellation_and_linked_inputs_preserve_project_execution_blockers() {
    let (owner, project, mut candidate) = super::tests::fixture();
    let home = project.parent().unwrap().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/lib.rs"), "").unwrap();
    std::fs::create_dir(project.join(".cargo")).unwrap();
    for index in 0..34 {
        std::fs::write(
            project.join(format!(".cargo/{index}.toml")),
            format!("include=['{}.toml']\n", index + 1),
        )
        .unwrap();
    }
    std::fs::write(project.join(".cargo/config.toml"), "include=['0.toml']\n").unwrap();
    let environment =
        || CargoOutputEnvironment::from_values(None, None, Some(home.as_os_str()), None);
    ProjectFormatSession::with_cargo_environment(
        HostPlatformScanner::new(),
        Default::default(),
        CancellationToken::new(),
        environment(),
    )
    .refresh(&mut candidate);
    assert_eq!(
        candidate
            .project_context
            .unwrap()
            .cargo_output
            .unwrap()
            .reason,
        "config_include_limit"
    );
    assert!(candidate.project_execution_blocker().is_some());
    let cancel = CancellationToken::new();
    cancel.cancel();
    ProjectFormatSession::with_cargo_environment(
        HostPlatformScanner::new(),
        Default::default(),
        cancel,
        environment(),
    )
    .refresh(&mut candidate);
    assert_eq!(
        candidate.project_context.unwrap().status,
        ProjectContextStatus::Unknown
    );
    ProjectFormatSession::with_cargo_environment(
        HostPlatformScanner::new(),
        ProjectFormatLimits {
            max_reserved_file_bytes: 0,
            ..Default::default()
        },
        CancellationToken::new(),
        environment(),
    )
    .refresh(&mut candidate);
    assert_eq!(candidate.project_context.unwrap().reason, "resource_limit");
    #[cfg(unix)]
    {
        std::fs::write(
            project.join(".cargo/config.toml"),
            "include=['linked.toml']\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("0.toml", project.join(".cargo/linked.toml")).unwrap();
        ProjectFormatSession::with_cargo_environment(
            HostPlatformScanner::new(),
            Default::default(),
            CancellationToken::new(),
            environment(),
        )
        .refresh(&mut candidate);
        assert_eq!(
            candidate
                .project_context
                .unwrap()
                .cargo_output
                .unwrap()
                .status,
            ProjectContextStatus::Unknown
        );
        assert!(candidate.project_execution_blocker().is_some());
    }
    drop(owner);
}
