use super::*;

#[cfg(unix)]
#[test]
fn captured_native_home_inputs_match_raw_cargo_output_without_authority() {
    use crate::junk::format::ProjectFormatSession;
    let raw: serde_json::Value =
        serde_json::from_str(sweepx_fixtures::project_junk::CARGO_NATIVE_HOME_ORACLE).unwrap();
    assert_eq!(raw["complete"], true);
    let records = raw["records"].as_array().unwrap();
    assert_eq!(records.len(), 9);
    for record in records {
        let (_owner, project, mut candidate) = super::super::tests::fixture();
        let root = project.parent().unwrap();
        let recorded_root = record["fixtureRoot"].as_str().unwrap();
        let remap = |value: &str| -> OsString {
            value
                .strip_prefix(recorded_root)
                .map(|relative| root.join(relative.trim_start_matches('/')).into_os_string())
                .unwrap_or_else(|| OsString::from(value))
        };
        let mut originals = Vec::new();
        for input in record["inputs"].as_array().unwrap() {
            let path = root.join(input["path"].as_str().unwrap());
            let bytes = input["utf8"].as_str().unwrap().as_bytes();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            originals.push((path, bytes));
        }
        let cargo_home = record["environment"]["CARGO_HOME"].as_str().map(remap);
        let user_home = record["environment"]["HOME"].as_str().map(remap);
        let mut environment = CargoOutputEnvironment::from_process_values(
            None,
            None,
            cargo_home.as_deref(),
            user_home.as_deref(),
        );
        let mut reserved = 0;
        let budget = budget(&mut reserved);
        let native_mode = record["nativeMode"].as_str().unwrap();
        let _ = environment.resolve_system_home_with(&CancellationToken::new(), &budget, || {
            match native_mode {
                "absent" => Err("cargo_home_unavailable"),
                "error" => Err("cargo_home_lookup_failed"),
                "range" => Err("resource_limit"),
                "present" | "empty" => Ok(remap(record["nativeHome"].as_str().unwrap())),
                other => panic!("unexpected native fixture mode {other}"),
            }
        });
        ProjectFormatSession::with_cargo_environment(
            sweepx_scanner::HostPlatformScanner::new(),
            Default::default(),
            CancellationToken::new(),
            environment,
        )
        .refresh(&mut candidate);
        let output = candidate.project_context.unwrap().cargo_output.unwrap();
        assert!(record["inputChanges"].as_array().unwrap().is_empty());
        assert!(record["cargo"]["boundedFailure"].is_null());
        if record["cargo"]["status"] == 0 {
            let metadata: serde_json::Value =
                serde_json::from_str(record["cargo"]["stdout"].as_str().unwrap()).unwrap();
            let target = PathBuf::from(remap(metadata["target_directory"].as_str().unwrap()));
            assert_eq!(
                output.status,
                ProjectContextStatus::Observed,
                "{} {output:?}",
                record["name"]
            );
            assert!(output.source_locations_observed);
            assert_eq!(
                output.candidate_path,
                if target == project.join("target") {
                    CargoOutputPathComparison::SameSpelling
                } else {
                    CargoOutputPathComparison::DifferentSpelling
                }
            );
            assert_eq!(
                output.source,
                Some(if native_mode == "empty" {
                    CargoOutputSource::ProjectConfig
                } else {
                    CargoOutputSource::CargoHomeConfig
                })
            );
            assert!(!target.exists(), "output directory was created");
        } else {
            assert_eq!(record["cargo"]["status"], 101);
            assert!(
                record["cargo"]["stderr"]
                    .as_str()
                    .unwrap()
                    .contains("couldn't find your home directory")
            );
            assert_eq!(output.status, ProjectContextStatus::Unknown);
            assert!(!output.source_locations_observed);
            assert_eq!(output.source, None);
        }
        assert!(candidate.project_execution_blocker().is_some());
        for (path, bytes) in originals {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        assert!(
            !serde_json::to_string(&output)
                .unwrap()
                .contains(root.to_str().unwrap())
        );
    }
}

fn budget(reserved: &mut usize) -> ScopeBudget<'_> {
    ScopeBudget {
        reserved_bytes: reserved,
        max_reserved_bytes: 1,
        file_bytes: 1,
        started: Instant::now(),
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn captured_home_queries_are_lazy_and_deduplicate_success_and_failure() {
    let cancel = CancellationToken::new();
    let mut reserved = 0;
    let budget = budget(&mut reserved);
    for observed in [
        Ok(OsString::from("native")),
        Ok(OsString::new()),
        Err("cargo_home_unavailable"),
        Err("cargo_home_lookup_failed"),
        Err("resource_limit"),
    ] {
        let mut environment = CargoOutputEnvironment::from_process_values(None, None, None, None);
        assert!(environment.system_home_pending);
        let expected = observed
            .as_ref()
            .map(|home| PathBuf::from(home).join(".cargo"))
            .map_err(|reason| *reason);
        let _ = environment.resolve_system_home_with(&cancel, &budget, || observed);
        assert_eq!(environment.home, expected);
        assert!(!environment.system_home_pending);
        let _ = environment.resolve_system_home_with(&cancel, &budget, || {
            panic!("native answer was queried twice")
        });
        assert_eq!(environment.home, expected);
    }
    for (home, user, expected) in [
        (Some("explicit"), None, "explicit"),
        (Some("explicit"), Some("fallback"), "explicit"),
        (None, Some("fallback"), "fallback/.cargo"),
        (Some(""), Some("fallback"), "fallback/.cargo"),
    ] {
        let mut environment = CargoOutputEnvironment::from_process_values(
            None,
            None,
            home.map(OsStr::new),
            user.map(OsStr::new),
        );
        assert!(!environment.system_home_pending);
        environment
            .resolve_system_home_with(&cancel, &budget, || {
                panic!("explicit home must not invoke the OS")
            })
            .unwrap();
        assert_eq!(environment.home.unwrap(), Path::new(expected));
    }
    let empty = CargoOutputEnvironment::from_process_values(None, None, None, Some(OsStr::new("")));
    assert!(empty.system_home_pending);
    assert_eq!(
        CargoOutputEnvironment::from_values(None, None, None, Some(OsStr::new("")))
            .home
            .unwrap(),
        Path::new(".cargo")
    );
    assert!(!CargoOutputEnvironment::from_values(None, None, None, None).system_home_pending);
}

#[test]
fn home_lookup_refuses_cancelled_or_expired_admission_and_cancelled_native_answers() {
    let cancel = CancellationToken::new();
    let mut reserved = 0;
    let mut budget = budget(&mut reserved);
    let pending = || CargoOutputEnvironment::from_process_values(None, None, None, None);
    budget.timeout = Duration::ZERO;
    assert_eq!(
        pending().resolve_system_home_with(&cancel, &budget, || panic!("expired lookup launched")),
        Err("deadline")
    );
    budget.timeout = Duration::from_secs(5);
    cancel.cancel();
    assert_eq!(
        pending()
            .resolve_system_home_with(&cancel, &budget, || panic!("cancelled lookup launched")),
        Err("cancelled")
    );
    let cancel = CancellationToken::new();
    let mut environment = pending();
    assert_eq!(
        environment.resolve_system_home_with(&cancel, &budget, || {
            cancel.cancel();
            Ok(OsString::from("late-native-answer"))
        }),
        Err("cancelled")
    );
    assert_eq!(environment.home, Err("cancelled"));
    assert!(!environment.system_home_pending);
}

// A fixture-only subprocess entry for the native interposition oracle. Parent environments
// remain unchanged; ordinary workspace runs return without any native lookup or output.
#[cfg(unix)]
#[test]
fn isolated_native_home_snapshot_probe() {
    use std::io::Write;
    let Some(record_path) = std::env::var_os("SWEEPX_NATIVE_HOME_RECORD") else {
        return;
    };
    let mut record = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(record_path)
        .unwrap();
    // Library/harness initialization can issue unrelated passwd requests. Explicit phase
    // markers let the independent interposer count this API's calls without discarding them
    // or guessing ownership from the requested buffer length.
    record
        .write_all(b"{\"phase\":\"capture_begin\"}\n")
        .unwrap();
    let mut environment = CargoOutputEnvironment::current();
    record.write_all(b"{\"phase\":\"capture_end\"}\n").unwrap();
    let pending = environment.system_home_pending;
    let cancel = CancellationToken::new();
    let mut reserved = 0;
    let budget = budget(&mut reserved);
    record.write_all(b"{\"phase\":\"lookup_begin\"}\n").unwrap();
    let first = environment.resolve_system_home_with(&cancel, &budget, super::super::home::lookup);
    record.write_all(b"{\"phase\":\"lookup_end\"}\n").unwrap();
    record.write_all(b"{\"phase\":\"repeat_begin\"}\n").unwrap();
    let second = environment
        .resolve_system_home_with(&cancel, &budget, || panic!("duplicate native lookup"));
    assert_eq!(first, second);
    record.write_all(b"{\"phase\":\"repeat_end\"}\n").unwrap();
    println!(
        "SWEEPX_NATIVE_HOME_JSON {}",
        serde_json::json!({
            "pendingBefore":pending,
            "home":environment.home.as_ref().ok().map(|home| home.to_str().unwrap()),
            "reason":environment.home.as_ref().err(),
            "pendingAfter":environment.system_home_pending,
        })
    );
}
