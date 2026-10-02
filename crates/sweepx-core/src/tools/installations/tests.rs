use super::*;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn rfc3339_formats_a_fixed_instant() {
    // 2026-01-02T03:04:05Z.
    let time = UNIX_EPOCH + Duration::from_secs(1_767_323_045);
    assert_eq!(rfc3339(time).as_deref(), Some("2026-01-02T03:04:05Z"));
}

#[test]
fn directory_newest_mtime_tracks_a_child_write() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let runner = ProbeRunner::new(
        super::super::ProbeLimits::default(),
        crate::CancellationToken::new(),
    );
    let before = Discovery::new(ToolDiscoveryLimits::default())
        .newest_mtime(&runner, root)
        .unwrap();

    let child = root.join("newer.bin");
    std::fs::write(&child, b"x").unwrap();
    // Bump mtime into the future so the comparison does not depend on filesystem clock
    // resolution equalizing the two writes.
    let future = UNIX_EPOCH + Duration::from_secs(4_000_000_000);
    let accessed = std::fs::FileTimes::new().set_modified(future);
    std::fs::File::open(&child)
        .unwrap()
        .set_times(accessed)
        .unwrap();

    let after = Discovery::new(ToolDiscoveryLimits::default())
        .newest_mtime(&runner, root)
        .unwrap();
    assert!(after > before);
    assert_eq!(after, future);
}

#[test]
fn run_trimmed_rejects_a_missing_executable_and_bad_exit() {
    let mut runner = ProbeRunner::new(
        super::super::ProbeLimits::default(),
        crate::CancellationToken::new(),
    );
    assert!(
        Discovery::new(ToolDiscoveryLimits::default())
            .answer(
                &mut runner,
                Path::new("/nonexistent/npm-xyz"),
                &["--version"],
                false
            )
            .is_none()
    );
    // `true` exits zero but prints nothing; an empty line must still be `None`.
    assert!(
        Discovery::new(ToolDiscoveryLimits::default())
            .answer(&mut runner, Path::new("/usr/bin/true"), &[], false)
            .is_none()
    );
}

#[test]
fn is_executable_file_distinguishes_bits() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("a");
    std::fs::write(&file, b"x").unwrap();
    #[cfg(unix)]
    {
        let runner = ProbeRunner::new(
            super::super::ProbeLimits::default(),
            crate::CancellationToken::new(),
        );
        assert!(
            Discovery::new(ToolDiscoveryLimits::default())
                .executable_identity(&runner, &file)
                .is_none()
        );
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let runner = ProbeRunner::new(
        super::super::ProbeLimits::default(),
        crate::CancellationToken::new(),
    );
    let mut discovery = Discovery::new(ToolDiscoveryLimits::default());
    assert!(discovery.executable_identity(&runner, &file).is_some());
    assert!(
        discovery
            .executable_identity(&runner, temp.path())
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn windows_path_discovers_cmd_shims_once() {
    let temp = tempfile::tempdir().unwrap();
    let shim = temp.path().join("npm.cmd");
    std::fs::write(&shim, b"@echo off").unwrap();
    std::fs::write(temp.path().join("npm.exe"), b"another launcher").unwrap();
    let paths = vec![temp.path().to_path_buf(), temp.path().to_path_buf()];
    let mut runner = ProbeRunner::new(
        super::super::ProbeLimits::default(),
        crate::CancellationToken::new(),
    );
    let report = discover_from(
        &mut runner,
        Discovery::new(ToolDiscoveryLimits::default()),
        Vec::new(),
        paths,
    );
    assert_eq!(report.installations.len(), 1);
    assert_eq!(report.installations[0].executable, shim);
    assert!(report.installations[0].is_path_default);
}

fn fresh_runner() -> ProbeRunner {
    ProbeRunner::new(
        super::super::ProbeLimits::default(),
        crate::CancellationToken::new(),
    )
}

#[test]
fn filesystem_calls_stop_before_budget_and_after_cancellation() {
    use std::cell::Cell;
    let calls = Cell::new(0);
    let cancel = crate::CancellationToken::new();
    let runner = ProbeRunner::new(super::super::ProbeLimits::default(), cancel.clone());
    let mut discovery = Discovery::new(ToolDiscoveryLimits {
        max_observations: 1,
        ..ToolDiscoveryLimits::default()
    });
    assert_eq!(
        discovery.observe(&runner, || {
            calls.set(calls.get() + 1);
            Ok(7)
        }),
        Some(7)
    );
    assert_eq!(
        discovery.observe(&runner, || {
            calls.set(calls.get() + 1);
            Ok(9)
        }),
        None
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(discovery.failure, Some(ToolDiscoveryFailure::ResourceLimit));
    let mut discovery = Discovery::new(ToolDiscoveryLimits::default());
    assert_eq!(
        discovery.observe(&runner, || {
            calls.set(calls.get() + 1);
            cancel.cancel();
            Ok(11)
        }),
        None
    );
    assert_eq!(
        discovery.observe(&runner, || {
            calls.set(calls.get() + 1);
            Ok(13)
        }),
        None
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(discovery.failure, Some(ToolDiscoveryFailure::Cancelled));
}

#[test]
fn expired_cancelled_and_zero_probe_budget_do_not_observe_the_host() {
    for (limits, cancelled, reason) in [
        (
            super::super::ProbeLimits {
                total_timeout: Duration::ZERO,
                ..super::super::ProbeLimits::default()
            },
            false,
            ToolDiscoveryFailure::ProbeBudget,
        ),
        (
            super::super::ProbeLimits {
                max_processes: 0,
                ..super::super::ProbeLimits::default()
            },
            false,
            ToolDiscoveryFailure::ProbeBudget,
        ),
        (
            super::super::ProbeLimits::default(),
            true,
            ToolDiscoveryFailure::Cancelled,
        ),
    ] {
        let cancel = crate::CancellationToken::new();
        if cancelled {
            cancel.cancel();
        }
        let mut runner = ProbeRunner::new(limits, cancel);
        let report =
            discover_npm_installations_with_limits(&mut runner, ToolDiscoveryLimits::default());
        assert!(report.installations.is_empty());
        assert_eq!(report.observations, 0);
        assert_eq!(report.retained_bytes, 0);
        assert_eq!(report.incomplete_reason, Some(reason));
    }
}

#[test]
fn partial_activity_is_unknown_and_complete_answers_are_invocation_local() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let file = root.join("payload");
    std::fs::write(&file, b"unchanged").unwrap();
    let future = UNIX_EPOCH + Duration::from_secs(4_000_000_000);
    std::fs::File::open(&file)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(future))
        .unwrap();
    let oracle = std::iter::once(std::fs::symlink_metadata(root).unwrap().modified().unwrap())
        .chain(std::fs::read_dir(root).unwrap().map(|entry| {
            std::fs::symlink_metadata(entry.unwrap().path())
                .unwrap()
                .modified()
                .unwrap()
        }))
        .max()
        .unwrap();
    let runner = fresh_runner();
    let mut short = Discovery::new(ToolDiscoveryLimits {
        max_observations: 2,
        ..ToolDiscoveryLimits::default()
    });
    assert_eq!(short.cache_newest_mtime(&runner, root), None);
    assert_eq!(short.observations, 2);
    assert_eq!(short.failure, Some(ToolDiscoveryFailure::ResourceLimit));
    let mut complete = Discovery::new(ToolDiscoveryLimits::default());
    assert_eq!(complete.cache_newest_mtime(&runner, root), Some(oracle));
    let calls = complete.observations;
    assert_eq!(complete.cache_newest_mtime(&runner, root), Some(oracle));
    assert_eq!(
        complete.observations, calls,
        "identical cache answers must not re-enumerate"
    );
    let later = future + Duration::from_secs(100);
    std::fs::File::open(&file)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(later))
        .unwrap();
    assert_eq!(
        Discovery::new(ToolDiscoveryLimits::default()).cache_newest_mtime(&runner, root),
        Some(later)
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"unchanged");
}

#[cfg(unix)]
#[test]
fn activity_observes_links_without_following_their_targets() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside");
    std::fs::write(&outside, b"user data").unwrap();
    let future = UNIX_EPOCH + Duration::from_secs(4_000_000_000);
    std::fs::File::open(&outside)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(future))
        .unwrap();
    let root = temp.path().join("cache");
    std::fs::create_dir(&root).unwrap();
    let link = root.join("linked");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let expected = std::fs::symlink_metadata(&root)
        .unwrap()
        .modified()
        .unwrap()
        .max(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .modified()
                .unwrap(),
        );
    let runner = fresh_runner();
    let mut discovery = Discovery::new(ToolDiscoveryLimits::default());
    assert_eq!(discovery.cache_newest_mtime(&runner, &root), Some(expected));
    assert_ne!(expected, future);
    let root_link = temp.path().join("cache-link");
    std::os::unix::fs::symlink(&root, &root_link).unwrap();
    assert_eq!(discovery.cache_newest_mtime(&runner, &root_link), None);
    assert_eq!(std::fs::read(&outside).unwrap(), b"user data");
}

#[test]
fn data_and_path_limits_decline_before_filesystem_calls() {
    let temp = tempfile::tempdir().unwrap();
    for limits in [
        ToolDiscoveryLimits {
            max_retained_bytes: 0,
            ..ToolDiscoveryLimits::default()
        },
        ToolDiscoveryLimits {
            max_path_bytes: 0,
            ..ToolDiscoveryLimits::default()
        },
    ] {
        let report = discover_from(
            &mut fresh_runner(),
            Discovery::new(limits),
            Vec::new(),
            [temp.path().to_path_buf()],
        );
        assert!(report.installations.is_empty());
        assert_eq!(report.observations, 0);
        assert_eq!(
            report.incomplete_reason,
            Some(ToolDiscoveryFailure::ResourceLimit)
        );
    }
}

#[test]
fn manager_enumeration_limits_keep_observed_positive_installations() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("known-npm");
    std::fs::write(&executable, b"not actually launched after exhaustion").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let versions = temp.path().join("versions");
    std::fs::create_dir(&versions).unwrap();
    for index in 0..128 {
        std::fs::create_dir(versions.join(format!("version-{index}"))).unwrap();
    }
    let layouts = vec![
        ManagerLayout {
            manager: "fixed",
            fixed_executable: Some(executable.clone()),
            versions_root: None,
            executable_from_version: &[],
        },
        ManagerLayout {
            manager: "versions",
            fixed_executable: None,
            versions_root: Some(versions),
            executable_from_version: &["npm"],
        },
    ];
    let report = discover_from(
        &mut fresh_runner(),
        Discovery::new(ToolDiscoveryLimits {
            max_observations: 5,
            ..ToolDiscoveryLimits::default()
        }),
        layouts,
        [],
    );
    assert_eq!(report.observations, 5);
    assert_eq!(
        report.incomplete_reason,
        Some(ToolDiscoveryFailure::ResourceLimit)
    );
    assert_eq!(report.installations.len(), 1);
    assert_eq!(report.installations[0].executable, executable);
    assert!(report.installations[0].cache.is_none());
    assert!(report.installations[0].cache_last_active_at.is_none());
    assert!(report.installations[0].tool_version.is_none());
}

#[test]
fn installation_limit_and_executable_memoization_are_shared() {
    let temp = tempfile::tempdir().unwrap();
    let runner = fresh_runner();
    let absent = temp.path().join("absent");
    let mut discovery = Discovery::new(ToolDiscoveryLimits::default());
    assert!(discovery.executable_identity(&runner, &absent).is_none());
    let calls = discovery.observations;
    assert!(discovery.executable_identity(&runner, &absent).is_none());
    assert_eq!(discovery.observations, calls);
    let mut discovery = Discovery::new(ToolDiscoveryLimits {
        max_installations: 1,
        ..ToolDiscoveryLimits::default()
    });
    let mut raw = Vec::new();
    let mut seen = BTreeSet::new();
    for label in ["one", "two"] {
        let path = temp.path().join(label);
        admit_identity(
            &mut discovery,
            &mut seen,
            &mut raw,
            "fixture",
            None,
            path.clone(),
            path,
        );
    }
    assert_eq!(raw.len(), 1);
    assert_eq!(discovery.failure, Some(ToolDiscoveryFailure::ResourceLimit));
}

#[test]
fn discovery_is_self_consistent_on_this_host() {
    let installations = discover_npm_installations(&mut ProbeRunner::new(
        super::super::ProbeLimits::default(),
        crate::CancellationToken::new(),
    ));
    // No executable reported twice after identity resolution.
    let mut identities: Vec<PathBuf> = installations
        .iter()
        .map(|i| std::fs::canonicalize(&i.executable).unwrap_or_else(|_| i.executable.clone()))
        .collect();
    let before = identities.len();
    identities.sort();
    identities.dedup();
    assert_eq!(before, identities.len());
    // At most one copy can be what a bare invocation resolves to.
    assert!(installations.iter().filter(|i| i.is_path_default).count() <= 1);
    // Every measured cache activity is RFC-3339, and a reported cache is absolute.
    for installation in &installations {
        if let Some(at) = &installation.cache_last_active_at {
            assert!(OffsetDateTime::parse(at, &Rfc3339).is_ok());
        }

        if let Some(cache) = &installation.cache {
            assert!(cache.is_absolute());
        }
    }
}

#[cfg(unix)]
#[test]
fn shared_cache_inventory_fits_one_enumeration_and_keeps_manager_precedence() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let cache = root.join("cache");
    let bin = root.join("bin");
    std::fs::create_dir(&cache).unwrap();
    std::fs::create_dir(&bin).unwrap();
    for index in 0..128 {
        std::fs::write(cache.join(format!("file-{index}")), b"preserved").unwrap();
    }
    let future = UNIX_EPOCH + Duration::from_secs(4_000_000_000);
    std::fs::File::open(cache.join("file-0"))
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(future))
        .unwrap();
    let cache_arg = cache.to_str().unwrap().replace('\'', "'\\''");
    // Fixed read-only test launchers; neither inherits tool configuration nor touches real caches.
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\nconfig) printf '%s\\n' '{cache_arg}' ;;\n--version) printf '%s\\n' '9.0.0' ;;\nesac\n"
    );
    let executables = [bin.join("tool-a"), bin.join("tool-b")];
    for executable in &executables {
        std::fs::write(executable, &script).unwrap();
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::os::unix::fs::symlink(&executables[0], bin.join("npm")).unwrap();
    let layouts = executables
        .iter()
        .map(|executable| ManagerLayout {
            manager: "fixture-manager",
            fixed_executable: Some(executable.clone()),
            versions_root: None,
            executable_from_version: &[],
        })
        .collect();
    // Enough for one 128-child cache walk plus executable probes, not two cache walks.
    let report = discover_from(
        &mut fresh_runner(),
        Discovery::new(ToolDiscoveryLimits {
            max_observations: 320,
            ..ToolDiscoveryLimits::default()
        }),
        layouts,
        [bin.clone(), bin],
    );
    if report.incomplete_reason.is_some() {
        eprintln!(
            "shared cache fixture retained at {:?}; installations={:?}; observations={}",
            temp.keep(),
            report.installations,
            report.observations
        );
    }
    assert_eq!(report.incomplete_reason, None);
    assert_eq!(report.installations.len(), 2);
    assert!(report.observations < 320);
    assert_eq!(
        report
            .installations
            .iter()
            .filter(|entry| entry.is_path_default)
            .count(),
        1
    );
    for installation in &report.installations {
        assert_eq!(installation.manager, "fixture-manager");
        assert_eq!(installation.cache.as_ref(), Some(&cache));
        assert_eq!(installation.tool_version.as_deref(), Some("9.0.0"));
        let at = OffsetDateTime::parse(
            installation.cache_last_active_at.as_ref().unwrap(),
            &Rfc3339,
        )
        .unwrap();
        assert_eq!(at.unix_timestamp(), 4_000_000_000);
    }
    // Independent filesystem oracle also detects host-created files instead of weakening counts.
    let observed: BTreeSet<_> = std::fs::read_dir(&cache)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let expected: BTreeSet<_> = (0..128)
        .map(|index| std::ffi::OsString::from(format!("file-{index}")))
        .collect();
    assert_eq!(observed, expected);
    for path in observed {
        assert_eq!(std::fs::read(cache.join(path)).unwrap(), b"preserved");
    }
}

#[test]
fn path_inventory_limit_retains_first_default_without_launching_after_exhaustion() {
    let temp = tempfile::tempdir().unwrap();
    let paths = [temp.path().join("one"), temp.path().join("two")];
    #[cfg(windows)]
    let name = "npm.cmd";
    #[cfg(not(windows))]
    let name = "npm";
    for directory in &paths {
        std::fs::create_dir(directory).unwrap();
        let executable = directory.join(name);
        std::fs::write(&executable, b"must not be launched").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let report = discover_from(
        &mut fresh_runner(),
        Discovery::new(ToolDiscoveryLimits {
            max_installations: 1,
            ..ToolDiscoveryLimits::default()
        }),
        Vec::new(),
        paths.clone(),
    );
    assert_eq!(
        report.incomplete_reason,
        Some(ToolDiscoveryFailure::ResourceLimit)
    );
    assert_eq!(report.installations.len(), 1);
    assert_eq!(report.installations[0].executable, paths[0].join(name));
    assert!(report.installations[0].is_path_default);
    assert!(report.installations[0].cache.is_none());
}

#[test]
fn missing_optional_paths_do_not_hide_failed_iterator_observations() {
    let runner = fresh_runner();
    let mut discovery = Discovery::new(ToolDiscoveryLimits::default());
    let missing = || Err::<(), _>(std::io::Error::from(std::io::ErrorKind::NotFound));
    assert!(discovery.observe_optional_path(&runner, missing).is_none());
    assert_eq!(discovery.failure, None);
    assert!(discovery.observe(&runner, missing).is_none());
    assert_eq!(
        discovery.failure,
        Some(ToolDiscoveryFailure::ObservationUnavailable)
    );
    assert_eq!(discovery.observations, 2);
}
