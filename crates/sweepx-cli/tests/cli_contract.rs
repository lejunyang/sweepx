use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::{Mutex, MutexGuard};

use assert_cmd::Command;
use serde_json::{Value, json};
use sweepx_protocol::{
    CapabilityCell, CapabilityRecordV1, CapabilityState, EvidenceClass, OsFamily,
};
use tempfile::TempDir;

fn duplicate_fixture() -> (TempDir, PathBuf) {
    // Content tests need a supported local filesystem, independently of the host's /tmp mount.
    #[cfg(target_os = "linux")]
    let fixture = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let fixture = TempDir::new().unwrap();
    #[cfg(unix)]
    let root = fixture.path().canonicalize().unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    (fixture, root)
}

#[test]
fn cargo_context_reports_current_declarations_in_both_locales_without_ownership() {
    let (_fixture, base) = duplicate_fixture();
    let root = base.join("project");
    fs::create_dir_all(root.join("nested/project/target")).unwrap();
    let project = root.join("nested/project");
    let manifest = project.join("Cargo.toml");
    let payload = project.join("target/personal");
    fs::write(&payload, b"preserved").unwrap();
    fs::create_dir(project.join(".cargo")).unwrap();
    let config_body = b"[build]\ntarget-dir='private/output'\n";
    fs::write(project.join(".cargo/config.toml"), config_body).unwrap();
    let cases = [
        (
            &b"[workspace]\nmembers=['crates/*']\n"[..],
            "observed",
            json!(1),
        ),
        (
            &b"[package]\nname='member'\nworkspace='../'\n"[..],
            "observed",
            Value::Null,
        ),
        (&b"[workspace]\nmembers=["[..], "invalid", Value::Null),
    ];
    for (body, status, patterns) in cases {
        fs::write(&manifest, body).unwrap();
        let mut contexts = Vec::new();
        for locale in ["en-US", "zh-CN"] {
            let output = cli_command()
                .timeout(std::time::Duration::from_secs(10))
                .args(["--locale", locale, "--format", "json", "--state-dir"])
                .arg(base.join(locale))
                .arg("junk")
                .arg(&root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let rows = report["candidates"].as_array().unwrap();
            assert_eq!(rows.len(), 1);
            let row = &rows[0];
            assert_eq!(row["ruleId"], "rust.target");
            assert_eq!(row["projectContext"]["profile"], "cargo_manifest");
            assert_eq!(row["projectContext"]["status"], status);
            let config = &row["projectContext"]["cargoConfig"];
            assert_eq!(config["consistency"], "non_atomic");
            assert_eq!(config["precedenceComplete"], false);
            assert_eq!(config["config"]["declared"], Value::Null);
            assert_eq!(config["configToml"]["declared"], true);
            assert!(!config.to_string().contains("private/output"));
            assert_eq!(
                row["projectContext"]["cargoManifest"]["memberPatterns"],
                patterns
            );
            assert_eq!(
                row["executionPolicy"],
                "require_project_ownership_and_activity"
            );
            for blocker in [
                "project_ownership_not_verified",
                "project_activity_not_verified",
            ] {
                assert!(
                    row["blockers"]
                        .as_array()
                        .unwrap()
                        .contains(&json!(blocker))
                );
            }
            contexts.push(row["projectContext"].clone());
            let human = cli_command()
                .args(["--locale", locale, "junk"])
                .arg(&root)
                .output()
                .unwrap();
            assert!(human.status.success());
            let text = String::from_utf8(human.stdout).unwrap();
            assert!(text.contains(if locale == "zh-CN" {
                "项目上下文"
            } else {
                "project context"
            }));
            assert!(text.contains(status));
            assert!(text.contains("target_dir_declared"));
            assert!(text.contains("precedenceComplete=false"));
            assert!(!text.contains("private/output"));
        }
        assert_eq!(
            fs::read(project.join(".cargo/config.toml")).unwrap(),
            config_body
        );
        assert_eq!(contexts[0], contexts[1]);
        assert_eq!(fs::read(&manifest).unwrap(), body);
        assert_eq!(fs::read(&payload).unwrap(), b"preserved");
    }
}

#[test]
fn actual_dart_recordings_keep_locale_stable_formats_and_workspace_notes() {
    for recording in sweepx_fixtures::project_junk::recordings::DART {
        let (_fixture, base) = duplicate_fixture();
        let root = base.join("project");
        for file in recording.files {
            let path = root.join(file.project_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, file.bytes).unwrap();
        }
        for locale in ["en-US", "zh-CN"] {
            let output = cli_command()
                .timeout(std::time::Duration::from_secs(10))
                .args(["--locale", locale, "--format", "json", "--state-dir"])
                .arg(base.join(locale))
                .arg("junk")
                .arg(&root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            let rows = report["candidates"].as_array().unwrap();
            assert_eq!(rows.len(), 1, "{}", recording.case_id);
            let row = &rows[0];
            assert_eq!(row["ruleId"], "dart.tool-state");
            assert_eq!(row["projectFormat"]["status"], "recognized");
            assert_eq!(
                row["projectFormat"]["profile"],
                "dart_pub_package_config_v2"
            );
            assert_eq!(row["executionPolicy"], "report_only");
            assert!(
                row["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("project_ownership_not_verified"))
            );
            assert!(
                row["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("project_activity_not_verified"))
            );
            for file in recording.files {
                assert_eq!(fs::read(root.join(file.project_path)).unwrap(), file.bytes);
            }
        }
    }
}

#[test]
fn duplicate_content_scan_reports_full_hashes_and_distinct_objects_in_both_locales() {
    let (_fixture, root) = duplicate_fixture();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("one"), b"abc").unwrap();
    fs::write(root.join("nested/two"), b"abc").unwrap();
    fs::write(root.join("different"), b"abd").unwrap();
    fs::hard_link(root.join("one"), root.join("alias")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("one"), root.join("link")).unwrap();
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    for locale in ["en-US", "zh-CN"] {
        let output = cli_command()
            .timeout(std::time::Duration::from_secs(10))
            .args([
                "--locale",
                locale,
                "--format",
                "json",
                "scan",
                "--no-state",
                "--duplicates",
                "--min-duplicate-bytes",
                "3",
            ])
            .arg(&root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let report = &value["data"]["duplicates"];
        assert_eq!(report["complete"], true);
        assert_eq!(report["options"]["minimumLogicalBytes"], "3");
        assert_eq!(report["hardLinkAliasesExcluded"], "1");
        let groups = report["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["sha256"], digest);
        assert_eq!(groups[0]["logicalBytes"], "3");
        let files = groups[0]["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        let mut identities = BTreeSet::new();
        for file in files {
            assert_eq!(file["objectType"], "file");
            assert!(file.get("nativeLocator").is_some());
            identities
                .insert(serde_json::to_string(&file["identity"]["platformFileIdentity"]).unwrap());
            assert_eq!(
                fs::read(file["displayPath"].as_str().unwrap()).unwrap(),
                b"abc"
            );
        }
        assert_eq!(identities.len(), 2);
        assert!(groups[0].get("keeper").is_none() && groups[0].get("reclaimableBytes").is_none());
    }
    let output = cli_command()
        .timeout(std::time::Duration::from_secs(10))
        .args([
            "--locale",
            "en-US",
            "scan",
            "--no-state",
            "--duplicates",
            "--min-duplicate-bytes",
            "3",
        ])
        .arg(&root)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Duplicate-content groups") && text.contains(digest));
    assert!(text.contains("does not establish disposability"));
    assert_eq!(fs::read(root.join("one")).unwrap(), b"abc");
    assert_eq!(fs::read(root.join("different")).unwrap(), b"abd");
}

#[test]
fn duplicate_limits_return_explicit_partial_reports_without_hashes() {
    let (_fixture, root) = duplicate_fixture();
    fs::write(root.join("one"), b"abc").unwrap();
    fs::write(root.join("two"), b"abc").unwrap();
    for (flag, limit, reason) in [
        ("--duplicate-read-bytes", "1", "read_limit"),
        ("--duplicate-max-files", "1", "retention_limit"),
    ] {
        let output = cli_command()
            .timeout(std::time::Duration::from_secs(10))
            .args([
                "--format",
                "json",
                "scan",
                "--no-state",
                "--duplicates",
                "--min-duplicate-bytes",
                "0",
                flag,
                limit,
            ])
            .arg(&root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(4));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "partial");
        let report = &value["data"]["duplicates"];
        assert_eq!(report["complete"], false);
        assert!(report["groups"].as_array().unwrap().is_empty());
        assert!(
            report["incompleteReasons"]
                .as_array()
                .unwrap()
                .contains(&json!(reason))
        );
        assert_eq!(report["readOperations"], "0");
    }
    assert_eq!(fs::read(root.join("two")).unwrap(), b"abc");
}

#[test]
fn duplicate_options_require_opt_in_and_plain_scan_has_no_content_report() {
    for args in [
        vec!["scan", "--min-duplicate-bytes", "1"],
        vec!["scan", "--duplicate-read-bytes", "1"],
        vec!["scan", "--duplicate-max-files", "1"],
        vec!["scan", "--duplicate-deadline-ms", "1"],
        vec!["scan", "--duplicates", "--tui"],
        vec!["scan", "--duplicates", "--large-files"],
        vec!["scan", "--duplicates", "--duplicate-read-bytes", "0"],
        vec!["scan", "--duplicates", "--duplicate-max-files", "100001"],
        vec!["scan", "--duplicates", "--duplicate-deadline-ms", "300001"],
    ] {
        cli_command().args(args).assert().code(2);
    }
    let (_fixture, root) = duplicate_fixture();
    let output = cli_command()
        .args(["--format", "json", "scan", "--no-state"])
        .arg(root)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["data"].get("duplicates").is_none());
}

#[test]
fn large_file_scan_reports_independent_ranked_metadata_in_both_locales() {
    let fixture = TempDir::new().unwrap();
    #[cfg(unix)]
    let root = fixture.path().canonicalize().unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    for (name, bytes) in [("small", 3), ("medium", 11), ("largest", 37)] {
        fs::write(root.join(name), vec![b'x'; bytes]).unwrap();
    }
    let mut expected: Vec<_> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| fs::symlink_metadata(path).unwrap().is_file())
        .map(|path| {
            (
                path.to_string_lossy().into_owned(),
                fs::symlink_metadata(path).unwrap().len(),
            )
        })
        .filter(|(_, length)| *length >= 11)
        .collect();
    expected.sort_unstable_by_key(|item| std::cmp::Reverse(item.1));
    expected.truncate(2);
    let mut previous = None;
    for locale in ["en-US", "zh-CN"] {
        let output = cli_command()
            .args([
                "--locale",
                locale,
                "--format",
                "json",
                "scan",
                "--no-state",
                "--large-files",
                "--min-file-bytes",
                "11",
                "--top-files",
                "2",
            ])
            .arg(&root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        let report = &value["data"]["largeFiles"];
        assert_eq!(report["complete"], true);
        assert_eq!(report["options"]["minimumLogicalBytes"], "11");
        let ranked: Vec<_> = report["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                assert_eq!(entry["objectType"], "file");
                assert!(
                    entry.get("allocatedBytes").is_some() && entry.get("nativeLocator").is_some()
                );
                assert!(entry.get("logicalBytes").unwrap().get("state").is_some());
                (
                    entry["displayPath"].as_str().unwrap().to_owned(),
                    entry["logicalBytes"]["value"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(ranked, expected);
        if let Some(previous) = &previous {
            assert_eq!(&ranked, previous);
        }
        previous = Some(ranked);
    }
    let output = cli_command()
        .args([
            "--locale",
            "en-US",
            "scan",
            "--no-state",
            "--large-files",
            "--min-file-bytes",
            "11",
        ])
        .arg(&root)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("Large files (report-only")
            && text.contains("Logical")
            && text.contains("Allocated")
            && text.contains("Large files are not junk")
    );
    assert_eq!(fs::read(root.join("largest")).unwrap(), vec![b'x'; 37]);
}

#[test]
fn large_file_options_refuse_conflicts_and_keep_plain_scan_output_unchanged() {
    for args in [
        vec!["scan", "--min-file-bytes", "1"],
        vec!["scan", "--top-files", "2"],
        vec!["scan", "--large-files", "--top-files", "0"],
        vec!["scan", "--large-files", "--top-files", "10001"],
        vec!["scan", "--large-files", "--tui"],
    ] {
        cli_command().args(args).assert().code(2);
    }
    let fixture = TempDir::new().unwrap();
    #[cfg(unix)]
    let root = fixture.path().canonicalize().unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    let output = cli_command()
        .args(["--format", "json", "scan", "--no-state"])
        .arg(root)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["data"].get("largeFiles").is_none());
}

fn cli_command() -> Command {
    Command::cargo_bin("sweepx").expect("binary available")
}

#[cfg(target_os = "linux")]
static LINUX_TEMP_ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(target_os = "linux")]
struct SyntheticLinuxProc {
    _lock: MutexGuard<'static, ()>,
    _proc: TempDir,
    _net_unix: PathBuf,
}

#[cfg(target_os = "linux")]
fn isolate_linux_temp_env() -> SyntheticLinuxProc {
    let lock = LINUX_TEMP_ENV_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let proc = TempDir::new().unwrap();
    fs::create_dir_all(proc.path().join("self")).unwrap();
    fs::write(proc.path().join("self/mountinfo"), b"").unwrap();
    let net_unix = proc.path().join("net-unix");
    fs::write(
        &net_unix,
        b"Num       RefCount Protocol Flags    Type St Inode Path\n",
    )
    .unwrap();
    // SAFETY: The module-wide lock makes these process-global seams test-serialized.
    unsafe {
        std::env::set_var("SWEEPX_TEST_LINUX_PROC_ROOT", proc.path());
        std::env::set_var("SWEEPX_TEST_LINUX_PROC_NET_UNIX", &net_unix);
        std::env::set_var("SWEEPX_TEST_LINUX_NOW_UNIX", "4000000000");
    }
    SyntheticLinuxProc {
        _lock: lock,
        _proc: proc,
        _net_unix: net_unix,
    }
}

#[cfg(target_os = "linux")]
impl Drop for SyntheticLinuxProc {
    fn drop(&mut self) {
        // SAFETY: Drop still holds the test-serialization lock.
        unsafe {
            std::env::remove_var("SWEEPX_TEST_LINUX_PROC_ROOT");
            std::env::remove_var("SWEEPX_TEST_LINUX_PROC_NET_UNIX");
            std::env::remove_var("SWEEPX_TEST_LINUX_TMP_ROOT");
            std::env::remove_var("SWEEPX_TEST_LINUX_NOW_UNIX");
        }
    }
}

#[cfg(target_os = "linux")]
fn only_child_directory(path: &std::path::Path) -> PathBuf {
    let entries = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_dir());
    entries.into_iter().next().unwrap()
}

#[cfg(unix)]
fn resolved_fixture_root(fixture: &TempDir) -> PathBuf {
    // Cache state deliberately refuses symlinked ancestors. macOS exposes `TMPDIR` through
    // `/var`, which links to `/private/var`, so preserve that production guard and give tests the
    // native path they would have received if the fixture were created below the real ancestor.
    // Keep this Unix-only: Windows canonicalization produces a verbatim `\\?\` path that the
    // state write path intentionally does not accept.
    fixture
        .path()
        .canonicalize()
        .expect("test fixture root must be resolvable")
}

#[cfg(unix)]
fn git_fixture_root(fixture: &TempDir) -> PathBuf {
    fixture
        .path()
        .canonicalize()
        .expect("Git test fixture root must be resolvable")
}

#[cfg(windows)]
fn git_fixture_root(fixture: &TempDir) -> PathBuf {
    fixture.path().to_path_buf()
}

#[cfg(unix)]
#[test]
fn locale_override_beats_environment_for_human_output() {
    let temp = TempDir::new().unwrap();
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("LANG", "en_US.UTF-8")
        .arg("--locale")
        .arg("zh-CN")
        .arg("--state-dir")
        .arg(temp.path())
        .arg("capabilities");

    let output = cmd.assert().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("语言: zh-CN"));
    assert!(!text.contains("Locale: zh-CN"));
}

#[test]
fn capabilities_json_uses_fixed_machine_keys() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("capabilities");

    let output = cmd.assert().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["schema"], "sweepx.output/v1");
    assert_eq!(json["kind"], "capabilities.result");
    assert!(json.get("requestId").is_some());
    assert!(json.get("request_id").is_none());
    assert_eq!(
        json["summary"]["commandCount"],
        if cfg!(target_os = "linux") {
            "13"
        } else {
            "12"
        }
    );
    assert_eq!(json["summary"]["capabilityCount"], "40");
    let commands = json["data"]["commands"].as_array().unwrap();
    assert_eq!(
        commands
            .iter()
            .filter(|command| command["mutating"] == true)
            .map(|command| command["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        if cfg!(target_os = "linux") {
            vec!["junk.clean-temp", "trash", "delete"]
        } else {
            vec!["junk.clean-temp", "trash"]
        }
    );
    assert!(commands.iter().all(|command| {
        !matches!(command["id"].as_str(), Some("plan" | "approve" | "execute"))
    }));
    let scan = commands.iter().find(|item| item["id"] == "scan").unwrap();
    assert_eq!(scan["state"], "degraded");
    assert_eq!(
        scan["reasonCode"],
        match std::env::consts::OS {
            "linux" => "LINUX_SCANNER_DEVELOPMENT",
            "macos" => "MACOS_SCANNER_DEVELOPMENT",
            "windows" => "WINDOWS_SCANNER_DEVELOPMENT",
            _ => "STUB_COMPILATION_ONLY",
        }
    );
    let cancel = commands.iter().find(|item| item["id"] == "cancel").unwrap();
    assert_eq!(cancel["state"], "disabled");
    let cargo_detect = commands
        .iter()
        .find(|item| item["id"] == "cleaner.cargo-detect")
        .unwrap();
    assert_eq!(cargo_detect["state"], "degraded");
    assert_eq!(
        cargo_detect["reasonCode"],
        "CARGO_TYPED_EVIDENCE_REPORT_ONLY"
    );
    let explain = commands
        .iter()
        .find(|item| item["id"] == "explain")
        .unwrap();
    assert_eq!(explain["state"], "qualified");
    let cache_status = commands
        .iter()
        .find(|item| item["id"] == "cache.status")
        .unwrap();
    // Cache status inspects the durable preview cache, which now exists on Windows too, so the
    // command is degraded (read-only) on every platform rather than disabled on one.
    assert_eq!(cache_status["state"], "degraded");
    let junk = commands.iter().find(|item| item["id"] == "junk").unwrap();
    assert_eq!(junk["state"], "degraded");
    assert_eq!(junk["mutating"], false);
    let linux_scan = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "linux"
                && item["qualificationKey"]["capability"] == "scan.local.directory"
        })
        .unwrap();
    assert_eq!(linux_scan["state"], "degraded");
    assert_eq!(linux_scan["reasonCode"], "LINUX_SCANNER_DEVELOPMENT");
    let explain_capability = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "linux"
                && item["qualificationKey"]["capability"] == "analysis.explain.scan_json"
        })
        .unwrap();
    assert_eq!(explain_capability["state"], "qualified");
    for os in ["macos", "windows"] {
        let explain = json["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == os
                    && item["qualificationKey"]["capability"] == "analysis.explain.scan_json"
            })
            .unwrap();
        assert_eq!(explain["state"], "qualified");

        let cleaner = json["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == os
                    && item["qualificationKey"]["capability"] == "catalog.cleaner.read"
            })
            .unwrap();
        // `qualified`, not `report_only`: both built-in manifests now admit the running Core, so
        // catalog reading is fully available rather than degraded. This assertion tracked the state
        // that a mistyped core range produced, not an intended one.
        assert_eq!(cleaner["state"], "qualified");

        let tui = json["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == os
                    && item["qualificationKey"]["capability"] == "scan.tui.live"
            })
            .unwrap();
        assert_eq!(tui["state"], "degraded");
        assert_eq!(
            tui["reasonCode"],
            if os == "macos" {
                "MACOS_LIVE_TUI_DEVELOPMENT"
            } else {
                "WINDOWS_LIVE_TUI_DEVELOPMENT"
            }
        );

        let ndjson = json["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == os
                    && item["qualificationKey"]["capability"] == "scan.ndjson.stream"
            })
            .unwrap();
        assert_eq!(ndjson["state"], "disabled");

        let durable_snapshot = json["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == os
                    && item["qualificationKey"]["capability"] == "operation.snapshot.durable"
            })
            .unwrap();
        // Durable snapshots are qualified on every supported platform now that Windows can
        // enforce a current-user-private state directory.
        assert_eq!(durable_snapshot["state"], "qualified");
    }

    let linux_tui = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "linux"
                && item["qualificationKey"]["capability"] == "scan.tui.live"
        })
        .unwrap();
    assert_eq!(linux_tui["state"], "degraded");

    let linux_ndjson = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "linux"
                && item["qualificationKey"]["capability"] == "scan.ndjson.stream"
        })
        .unwrap();
    assert_eq!(linux_ndjson["state"], "disabled");

    let linux_snapshot = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "linux"
                && item["qualificationKey"]["capability"] == "operation.snapshot.durable"
        })
        .unwrap();
    assert_eq!(linux_snapshot["state"], "qualified");

    let linux_replay = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "linux"
                && item["qualificationKey"]["capability"]
                    == CapabilityCell::OPERATION_EVENT_COMPLETED_REPLAY
        })
        .unwrap();
    assert_eq!(linux_replay["state"], "degraded");
    assert_eq!(
        linux_replay["reasonCode"],
        "LINUX_COMPLETED_EVENT_REPLAY_SUPPORTED"
    );
    let linux_cache_preview = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "linux"
                && item["qualificationKey"]["capability"] == "cache.preview.inspect"
        })
        .unwrap();
    assert_eq!(linux_cache_preview["state"], "degraded");
    assert_eq!(
        linux_cache_preview["reasonCode"],
        "CACHE_PREVIEW_INSPECTION_READ_ONLY"
    );
    for os in ["macos", "windows"] {
        let replay = json["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == os
                    && item["qualificationKey"]["capability"]
                        == CapabilityCell::OPERATION_EVENT_COMPLETED_REPLAY
            })
            .unwrap();
        assert_eq!(replay["state"], "disabled");
        assert_eq!(
            replay["reasonCode"],
            "COMPLETED_EVENT_REPLAY_JOURNAL_UNAVAILABLE"
        );

        let cache_preview = json["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == os
                    && item["qualificationKey"]["capability"] == "cache.preview.inspect"
            })
            .unwrap();
        assert_eq!(cache_preview["state"], "degraded");
        assert_eq!(
            cache_preview["reasonCode"],
            "CACHE_PREVIEW_INSPECTION_READ_ONLY"
        );
    }

    let windows_scan = json["data"]["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["qualificationKey"]["osFamily"] == "windows"
                && item["qualificationKey"]["capability"] == "scan.local.directory"
        })
        .unwrap();
    assert_eq!(windows_scan["state"], "degraded");
    assert_eq!(windows_scan["reasonCode"], "WINDOWS_SCANNER_DEVELOPMENT");

    let capability_values = json["data"]["capabilities"].as_array().unwrap();
    let records = capability_values
        .iter()
        .map(|value| {
            let record: CapabilityRecordV1 = serde_json::from_value(value.clone()).unwrap();
            if record.state == CapabilityState::Qualified {
                record.validate_at(&record.recorded_at).unwrap();
            } else {
                record.validate().unwrap();
            }
            record
        })
        .collect::<Vec<_>>();
    assert_eq!(
        json["summary"]["capabilityCount"],
        records.len().to_string()
    );

    let unique_keys = records
        .iter()
        .map(|record| serde_json::to_string(&record.qualification_key).unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(unique_keys.len(), records.len());
    assert!(
        records
            .iter()
            .all(|record| !record.is_qualified_mutation_at(&record.recorded_at))
    );
    assert!(
        records
            .iter()
            .all(|record| { record.qualification_key.capability.as_str() != "mutation.local.any" })
    );

    let mutation_cells = [
        (
            CapabilityCell::TRASH_LOCAL_FILE,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
        ),
        (
            CapabilityCell::TRASH_LOCAL_DIRECTORY,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
        ),
        (
            CapabilityCell::PERMANENT_LOCAL_FILE,
            "PERMANENT_QUALIFICATION_ABSENT",
        ),
        (
            CapabilityCell::PERMANENT_LOCAL_DIRECTORY,
            "PERMANENT_QUALIFICATION_ABSENT",
        ),
        (
            CapabilityCell::PERMANENT_LOCAL_LINK,
            "PERMANENT_QUALIFICATION_ABSENT",
        ),
    ];
    for os_family in [OsFamily::Linux, OsFamily::Macos, OsFamily::Windows] {
        for (capability, reason_code) in mutation_cells {
            let matches = records
                .iter()
                .filter(|record| {
                    record.qualification_key.os_family == os_family
                        && record.qualification_key.capability.as_str() == capability
                })
                .collect::<Vec<_>>();
            assert_eq!(
                matches.len(),
                1,
                "missing or duplicate {os_family:?}/{capability}"
            );
            let record = matches[0];
            if os_family == current_os_family_for_test()
                && matches!(
                    capability,
                    CapabilityCell::TRASH_LOCAL_FILE | CapabilityCell::TRASH_LOCAL_DIRECTORY
                )
            {
                assert_eq!(record.state, CapabilityState::Degraded);
                assert_eq!(
                    record.reason_code,
                    "TRASH_PREVIEW_REQUIRES_CONFIRMATION_AND_REVALIDATION"
                );
            } else if os_family == OsFamily::Linux
                && cfg!(target_os = "linux")
                && capability == CapabilityCell::PERMANENT_LOCAL_FILE
            {
                assert_eq!(record.state, CapabilityState::Degraded);
                assert_eq!(record.reason_code, "LINUX_PERMANENT_FILE_PREVIEW");
            } else if os_family == OsFamily::Linux
                && cfg!(target_os = "linux")
                && capability == CapabilityCell::PERMANENT_LOCAL_DIRECTORY
            {
                assert_eq!(record.state, CapabilityState::Degraded);
                assert_eq!(record.reason_code, "LINUX_PERMANENT_DIRECTORY_PREVIEW");
            } else {
                assert_eq!(record.state, CapabilityState::Disabled);
                assert_eq!(record.reason_code, reason_code);
            }
            assert!(matches!(
                record.evidence.evidence_class,
                EvidenceClass::FixtureConformanceOnly | EvidenceClass::Incomplete
            ));
        }
    }

    let linux_trash_file = records
        .iter()
        .find(|record| {
            record.qualification_key.os_family == OsFamily::Linux
                && record.qualification_key.capability.as_str() == CapabilityCell::TRASH_LOCAL_FILE
        })
        .unwrap();
    assert_eq!(
        linux_trash_file.evidence.evidence_class,
        EvidenceClass::FixtureConformanceOnly
    );
    assert!(
        records
            .iter()
            .filter(|record| {
                record.qualification_key.capability.is_mutation()
                    && !(record.qualification_key.os_family == OsFamily::Linux
                        && record.qualification_key.capability.as_str()
                            == CapabilityCell::TRASH_LOCAL_FILE)
            })
            .all(|record| record.evidence.evidence_class == EvidenceClass::Incomplete)
    );
}

fn current_os_family_for_test() -> OsFamily {
    match std::env::consts::OS {
        "windows" => OsFamily::Windows,
        "macos" => OsFamily::Macos,
        _ => OsFamily::Linux,
    }
}

#[cfg(unix)]
#[test]
fn explain_scan_json_returns_explanation_result() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    fs::write(&scan_json, sample_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("explain")
        .arg("--scan-json")
        .arg(&scan_json);

    let output = cmd.assert().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["kind"], "explanation.result");
    assert_eq!(json["summary"]["inputMode"], "scan_json");
    assert_eq!(
        json["data"]["explanations"][0]["candidate"]["path"]["displayPath"],
        "/tmp/demo"
    );
}

#[cfg(unix)]
#[test]
fn explain_human_output_respects_selected_locale() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    fs::write(&scan_json, sample_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("LANG", "en_US.UTF-8")
        .arg("--locale")
        .arg("zh-CN")
        .arg("explain")
        .arg("--scan-json")
        .arg(&scan_json);

    let output = cmd.assert().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("已从扫描"));
    assert!(!text.contains("Generated"));
}

#[cfg(unix)]
#[test]
fn explain_rejects_relative_scan_json_path() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("explain")
        .arg("--scan-json")
        .arg("relative.json");

    let output = cmd.assert().get_output().stderr.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("analysis input path must be absolute"));
}

#[test]
fn explain_rejects_zero_input_limit() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    fs::write(&scan_json, sample_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("explain")
        .arg("--scan-json")
        .arg(&scan_json)
        .arg("--max-input-bytes")
        .arg("0");

    let output = cmd.assert().get_output().stderr.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("analysis input must be a positive bounded byte limit"));
}

#[test]
fn explain_rejects_oversize_input() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    fs::write(&scan_json, sample_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("explain")
        .arg("--scan-json")
        .arg(&scan_json)
        .arg("--max-input-bytes")
        .arg("16");

    let output = cmd.assert().get_output().stderr.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("analysis input exceeds byte limit"));
}

#[test]
fn cleaner_list_json_uses_cleaner_result_contract() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("cleaner")
        .arg("list");

    let output = cmd.assert().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["kind"], "cleaner.result");
    assert_eq!(json["summary"]["command"], "cleaner.list");
    assert_eq!(json["data"]["cleaners"][0]["id"], "org.sweepx.cargo-target");
    // `ok`, not `partial`: every shipped manifest admits the running Core. `partial` here recorded
    // a mistyped core range in the chromium manifest rather than a property worth protecting.
    assert_eq!(json["status"], "ok");
    assert_eq!(json["summary"]["incompatibleCleanerCount"], "0");
    assert_eq!(
        json["data"]["cleaners"][0]["compatibility"]["state"],
        "compatible"
    );
}

/// Both shipped packages are compatible, so `show` succeeds for either one.
///
/// This test previously asserted exit 12 on the chromium package. That only passed because its
/// manifest carried a mistyped `>=1.0.0` core range, so it was pinning a defect rather than a
/// contract. The CLI cannot load a cleaner from a caller-supplied directory, so an incompatible
/// package cannot be constructed at this layer at all; the refusal itself is covered by
/// `the_compat_gate_refuses_a_package_that_excludes_the_running_core` in sweepx-core, which builds
/// the incompatible case from bytes.
#[test]
fn cleaner_show_succeeds_for_the_chromium_builtin() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("cleaner")
        .arg("show")
        .arg("org.sweepx.chromium-rebuildable-cache");

    let output = cmd.assert().code(0).get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(
        json["data"]["cleaner"]["compatibility"]["state"],
        "compatible"
    );
}

#[test]
fn experimental_cargo_detect_scans_with_compatible_builtin() {
    let fixture = TempDir::new().unwrap();
    let base = fs::canonicalize(fixture.path()).unwrap();
    let root = base.join("workspace");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("target")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("cleaner")
        .arg("cargo-detect")
        .arg(&root);

    let output = cmd.assert().get_output().clone();
    assert!(
        !output.stdout.is_empty(),
        "junk --system produced no JSON; exit={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cleaner.result");
    assert_eq!(json["summary"]["command"], "cleaner.cargo-detect");
    assert_eq!(json["summary"]["experimental"], true);
    assert_eq!(json["summary"]["liveOnly"], true);
    assert_eq!(json["summary"]["matchCount"], "0");
    assert_eq!(json["summary"]["hintCount"], "0");
    assert_eq!(json["data"]["readOnly"], true);
    assert_eq!(json["data"]["candidateAllowed"], false);
    assert_eq!(json["data"]["planAllowed"], false);
    assert_eq!(json["data"]["approvalAllowed"], false);
    assert_eq!(json["data"]["executionAllowed"], false);
    assert_eq!(json["data"]["builtinManifestCompatible"], true);
    assert_eq!(json["data"]["matchCount"], "0");
    assert_eq!(json["data"]["hintCount"], "0");
    assert_eq!(json["data"]["matches"], Value::Array(Vec::new()));
    assert_eq!(json["data"]["hints"], Value::Array(Vec::new()));
    assert!(output.stderr.is_empty());
}

#[test]
fn cargo_detect_compatibility_gate_does_not_disclose_environment_values() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("workspace");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let target_sentinel = "sweepx-secret-target-dir-sentinel";
    let build_target_sentinel = "sweepx-secret-build-target-dir-sentinel";
    let home_sentinel = "sweepx-secret-cargo-home-sentinel";

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("CARGO_TARGET_DIR", target_sentinel)
        .env("CARGO_BUILD_TARGET_DIR", build_target_sentinel)
        .env("CARGO_HOME", home_sentinel)
        .arg("--format")
        .arg("json")
        .arg("cleaner")
        .arg("cargo-detect")
        .arg(&root);

    let output = cmd.assert().get_output().clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    for secret in [target_sentinel, build_target_sentinel, home_sentinel] {
        assert!(!stdout.contains(secret));
        assert!(!stderr.contains(secret));
    }
}

#[test]
fn trash_moves_ordinary_paths_without_confirmation_in_machine_invocations() {
    let fixture = TempDir::new().unwrap();
    let path = fixture.path().join("keep.txt");
    fs::write(&path, b"keep").unwrap();

    // New policy: an ordinary file goes straight to the recoverable Trash even from a scripted,
    // non-interactive caller. The protection boundary is the protected/important path guards, not
    // a confirmation prompt, and permanent deletion is still never a fallback.
    let mut cmd = cli_command();
    cmd.arg("--format").arg("json").arg("trash").arg(&path);
    let output = cmd.assert().code(0).get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["recoverable"], true);
    assert_eq!(json["permanentFallback"], false);
    assert!(!path.exists());
}

#[test]
fn trash_rejects_relative_paths_without_changing_them() {
    let mut cmd = cli_command();
    cmd.arg("trash").arg("relative.txt");
    cmd.assert().code(8);
}

#[cfg(target_os = "linux")]
#[test]
fn permanent_delete_requires_a_foreground_terminal_before_creating_state() {
    let fixture = TempDir::new().unwrap();
    let path = fixture.path().join("keep.txt");
    let state = fixture.path().join("state");
    fs::write(&path, b"keep").unwrap();

    let mut cmd = cli_command();
    cmd.arg("--state-dir").arg(&state).arg("delete").arg(&path);
    cmd.assert().code(8);

    assert!(path.exists());
    assert!(!state.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn noninteractive_permanent_delete_leaves_directory_and_link_inputs_unchanged() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().canonicalize().unwrap();
    let state = root.join("state");
    let directory = root.join("directory");
    fs::create_dir(&directory).unwrap();
    let target = root.join("target");
    fs::write(&target, b"keep").unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    for path in [&directory, &link] {
        let mut cmd = cli_command();
        cmd.arg("--state-dir").arg(&state).arg("delete").arg(path);
        cmd.assert().code(8);
        assert!(path.exists());
    }
    assert!(target.exists());
    assert!(!state.exists());
}

#[test]
fn junk_tui_rejects_nonterminals_machine_formats_and_conflicting_modes_before_scan() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path();
    fs::write(root.join("payload"), b"unchanged").unwrap();
    let state = root.join("state");
    for args in [
        vec!["junk", "--tui"],
        vec!["--format", "json", "junk", "--tui"],
        vec!["junk", "--tui", "--system"],
        vec!["junk", "--tui", "--trash"],
        vec!["junk", "--tui", "--timings"],
    ] {
        let mut cmd = cli_command();
        cmd.timeout(std::time::Duration::from_secs(5));
        cmd.arg("--state-dir").arg(&state).args(args).arg(root);
        cmd.assert().code(2);
        assert_eq!(fs::read(root.join("payload")).unwrap(), b"unchanged");
        assert!(!state.exists());
    }
}

#[test]
fn system_junk_tui_requires_a_terminal_before_discovery_or_state_creation() {
    let fixture = TempDir::new().unwrap();
    let state = fixture.path().join("state");
    let mut cmd = cli_command();
    cmd.timeout(std::time::Duration::from_secs(5));
    cmd.arg("--state-dir")
        .arg(&state)
        .args(["junk", "--tui", "--system"]);
    cmd.assert()
        .code(2)
        .stderr(predicates::str::contains("terminal"));
    assert!(!state.exists());
}

#[test]
fn junk_temp_cleanup_requires_a_foreground_human_confirmation() {
    let mut cmd = cli_command();
    cmd.timeout(std::time::Duration::from_secs(10));
    cmd.arg("--format")
        .arg("json")
        .arg("junk")
        .arg("--system")
        .arg("--clean-temp");
    cmd.assert()
        .code(2)
        .stderr(predicates::str::contains("foreground interactive terminal"));
}

#[test]
fn junk_temp_cleanup_requires_system_discovery() {
    let mut cmd = cli_command();
    cmd.arg("junk").arg("--clean-temp");
    cmd.assert().code(2);
}

#[cfg(unix)]
#[test]
fn project_junk_scan_does_not_launch_npm_inventory() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("project");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("Cargo.toml"), b"[workspace]").unwrap();
    let shim = fixture.path().join("npm");
    let sentinel = fixture.path().join("npm-was-launched");
    fs::write(
        &shim,
        b"#!/bin/sh\n: > \"$SWEEPX_PROBE_SENTINEL\"\nprintf '/unrelated/cache\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    let mut command = cli_command();
    command
        .env("PATH", fixture.path())
        .env("SWEEPX_PROBE_SENTINEL", &sentinel)
        .args(["--format", "json", "junk"])
        .arg(&root);
    let output = command.assert().success().get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["toolInstallations"], json!([]));
    assert!(
        json["npmDiscovery"].is_null(),
        "project-only scans do not observe npm inventory"
    );
    assert!(
        !sentinel.exists(),
        "project scanning must not invoke unrelated npm"
    );
}

#[test]
fn junk_timings_preserve_report_and_account_for_phases() {
    let fixture = TempDir::new().unwrap();
    let root = git_fixture_root(&fixture);
    let state = TempDir::new().unwrap();
    let state_root = git_fixture_root(&state);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join("target/artifact"), b"payload").unwrap();
    let mut cmd = cli_command();
    let output = cmd
        .args(["--format", "json", "--state-dir"])
        .arg(&state_root)
        .args(["junk", "--timings"])
        .arg(&root)
        .timeout(std::time::Duration::from_secs(20))
        .assert()
        .success()
        .get_output()
        .clone();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "sweepx.junk.result/v1");
    assert_eq!(report["candidateCount"], 1);
    assert_eq!(
        report["candidates"][0]["path"],
        root.join("target").display().to_string()
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let timings = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value["schema"] == "sweepx.junk.timings/v1")
        .collect::<Vec<_>>();
    assert_eq!(timings.len(), 1);
    let timing = &timings[0];
    assert_eq!(timing["complete"], true);
    assert_eq!(timing["rootCount"], 1);
    assert_eq!(timing["rootCacheHits"], 0);
    assert_eq!(timing["rootCacheMisses"], 1);
    assert_eq!(timing["candidateCount"], report["candidateCount"]);
    let phases = timing["phasesNs"].as_object().unwrap();
    for required in [
        "discovery",
        "setup",
        "rootCacheValidation",
        "subtreeCacheValidation",
        "traversal",
        "classification",
        "projectFormats",
        "gitEvidence",
        "cacheWrite",
        "report",
    ] {
        assert!(phases.contains_key(required), "missing phase {required}");
    }
    let accounted: u64 = phases.values().map(|value| value.as_u64().unwrap()).sum();
    assert!(accounted <= timing["totalNs"].as_u64().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn junk_scan_reports_only_marker_bound_project_artifacts() {
    let fixture = TempDir::new().unwrap();
    fs::write(
        fixture.path().join("Cargo.toml"),
        b"[workspace]\nmembers=[]\n",
    )
    .unwrap();
    fs::create_dir(fixture.path().join("target")).unwrap();
    fs::create_dir_all(fixture.path().join("vendor/package/dist")).unwrap();

    let mut cmd = cli_command();
    cmd.arg("--format")
        .arg("json")
        .arg("junk")
        .arg(fixture.path());
    let output = cmd.assert().get_output().clone();
    assert!(
        !output.stdout.is_empty(),
        "temp junk scan produced no JSON; exit={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let candidates = json["candidates"].as_array().unwrap();
    assert!(candidates.iter().any(|candidate| {
        candidate["ruleId"] == "rust.target"
            && candidate["path"] == fixture.path().join("target").display().to_string()
    }));
    assert!(candidates.iter().all(|candidate| {
        candidate["path"]
            != fixture
                .path()
                .join("vendor/package/dist")
                .display()
                .to_string()
    }));
    let target = candidates
        .iter()
        .find(|candidate| candidate["ruleId"] == "rust.target")
        .unwrap();
    assert_eq!(target["reclaimable"]["state"], "known");
    assert!(target["reclaimable"].get("value").is_some());
    assert_eq!(target["classification"], "known_generated");
    assert_eq!(target["confidence"], "medium");
    assert_eq!(target["git"], Value::Null);
    assert_eq!(json["incompleteSizeCount"], 0);
}

#[test]
fn junk_project_layout_corpus_keeps_machine_rules_and_source_payloads() {
    #[cfg(target_os = "linux")]
    let fixture = TempDir::new_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let fixture = TempDir::new().unwrap();
    #[cfg(unix)]
    let root = resolved_fixture_root(&fixture);
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    let cases = sweepx_fixtures::project_junk::generate(&root).unwrap();
    for locale in ["en-US", "zh-CN"] {
        let mut command = cli_command();
        command
            .timeout(std::time::Duration::from_secs(20))
            .args(["--locale", locale, "--format", "json", "junk"]);
        for (_, path) in &cases {
            command.arg(path);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        let observed = json["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| {
                assert_eq!(candidate["risk"], "R3");
                if candidate["ruleId"] == "dart.tool-state"
                    || candidate["ruleId"] == "node.sveltekit-output"
                {
                    assert_eq!(candidate["classification"], "recognized_generated_format");
                    assert_eq!(candidate["projectFormat"]["status"], "recognized");
                    assert_eq!(candidate["confidence"], "medium");
                    assert!(
                        candidate["blockers"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|b| b == "project_ownership_not_verified")
                    );
                } else {
                    assert_eq!(candidate["classification"], "known_generated");
                    assert!(candidate["projectFormat"].is_null());
                }
                assert!(
                    candidate["evidence"]
                        .as_str()
                        .unwrap()
                        .contains("layout only")
                );
                (
                    PathBuf::from(candidate["path"].as_str().unwrap()),
                    candidate["ruleId"].as_str().unwrap().to_string(),
                )
            })
            .collect::<BTreeSet<_>>();
        let expected = cases
            .iter()
            .flat_map(|(case, path)| {
                case.candidates
                    .iter()
                    .map(|(candidate, rule)| (path.join(candidate), (*rule).to_string()))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(observed, expected);
    }
    for (case, path) in &cases {
        for (file, payload) in case.files {
            assert_eq!(fs::read(path.join(file)).unwrap(), payload.as_bytes());
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn junk_system_reports_incomplete_discovery_without_following_layout_ancestor_links() {
    let fixture = TempDir::new().unwrap();
    let root = resolved_fixture_root(&fixture);
    let home = root.join("home");
    let cache = home.join("Library/Caches/Homebrew");
    let support = home.join("Library/Application Support");
    let outside = root.join("unrelated-browser-data");
    let empty_path = root.join("empty-path");
    fs::create_dir_all(cache.join("downloads")).unwrap();
    fs::create_dir_all(&support).unwrap();
    fs::create_dir_all(outside.join("Chrome/Default/GPUCache")).unwrap();
    fs::create_dir(&empty_path).unwrap();
    std::os::unix::fs::symlink(&outside, support.join("Google")).unwrap();
    let mut cmd = cli_command();
    cmd.env("HOME", &home)
        .env("PATH", &empty_path)
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(root.join("private-state"))
        .args(["junk", "--system"]);
    let output = cmd.assert().code(4).get_output().clone();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "partial");
    assert_eq!(report["layoutDiscovery"]["complete"], false);
    assert_eq!(
        report["layoutDiscovery"]["incompleteReason"],
        "observation_unavailable"
    );
    let candidates = report["candidates"].as_array().unwrap();
    assert!(
        candidates
            .iter()
            .any(|row| row["ruleId"] == "macos.homebrew-cache"
                && row["path"] == cache.display().to_string())
    );
    assert!(
        candidates
            .iter()
            .all(|row| !row["path"].as_str().unwrap().contains("GPUCache"))
    );
}

#[test]
fn junk_git_observes_current_global_configuration_selected_by_environment() {
    let fixture = TempDir::new().unwrap();
    let base = git_fixture_root(&fixture);
    let root = base.join("project");
    let home = base.join("home");
    fs::create_dir(&home).unwrap();
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    assert!(
        std::process::Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(&root)
            .status()
            .unwrap()
            .success()
    );
    let config = base.join("selected-global-config");
    let excludes = base.join("excludes");
    fs::write(&excludes, b"target/\n").unwrap();
    assert!(
        std::process::Command::new("git")
            .arg("config")
            .arg("--file")
            .arg(&config)
            .arg("core.excludesFile")
            .arg(&excludes)
            .status()
            .unwrap()
            .success()
    );
    for ignored in [true, false] {
        if !ignored {
            fs::write(&excludes, b"").unwrap();
        }
        let configure = |command: &mut std::process::Command| {
            command
                .env("HOME", &home)
                .env("XDG_CONFIG_HOME", &home)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", &config);
        };
        let mut oracle = std::process::Command::new("git");
        configure(&mut oracle);
        assert_eq!(
            oracle
                .arg("-C")
                .arg(&root)
                .args(["check-ignore", "--quiet", "--", "target"])
                .status()
                .unwrap()
                .code(),
            Some(if ignored { 0 } else { 1 })
        );
        let mut command = cli_command();
        command
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &config);
        let output = command
            .args(["--format", "json", "--state-dir"])
            .arg(base.join("state"))
            .args(["junk"])
            .arg(&root)
            .timeout(std::time::Duration::from_secs(15))
            .assert()
            .success()
            .get_output()
            .clone();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["candidateCount"], 1);
        assert_eq!(
            report["candidates"][0]["confidence"],
            if ignored { "high" } else { "medium" }
        );
        assert_eq!(
            report["candidates"][0]["blockers"],
            json!([
                "project_ownership_not_verified",
                "project_activity_not_verified"
            ])
        );
    }
}

#[test]
fn project_execution_policy_is_locale_stable_and_generic_outputs_stay_visible() {
    let fixture = TempDir::new().unwrap();
    #[cfg(unix)]
    let root = resolved_fixture_root(&fixture);
    #[cfg(windows)]
    let root = fixture.path().to_path_buf();
    fs::write(root.join("package.json"), b"{}\n").unwrap();
    fs::create_dir(root.join("dist")).unwrap();
    fs::write(root.join("dist/personal-data"), b"preserve personal data").unwrap();
    assert!(
        std::process::Command::new("git")
            .args(["init", "--quiet"])
            .arg(&root)
            .status()
            .unwrap()
            .success()
    );
    for locale in ["en-US", "zh-CN"] {
        let output = cli_command()
            .args(["--locale", locale, "--format", "json", "junk"])
            .arg(&root)
            .assert()
            .success()
            .get_output()
            .clone();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["candidateCount"], 1);
        let row = &report["candidates"][0];
        assert_eq!(row["ruleId"], "project.build-output");
        assert_eq!(row["executionPolicy"], "report_only");
        assert_eq!(
            row["blockers"],
            json!(["project_report_only", "project_activity_not_verified"])
        );
        let human = cli_command()
            .args(["--locale", locale, "junk"])
            .arg(&root)
            .assert()
            .success()
            .get_output()
            .clone();
        let text = String::from_utf8(human.stdout).unwrap();
        assert!(text.contains(if locale == "en-US" {
            "Trash blocked: report-only rule or unverified ownership/activity"
        } else {
            "回收受限：规则仅报告或所有权/活动未核验"
        }));
        assert_eq!(
            fs::read(root.join("dist/personal-data")).unwrap(),
            b"preserve personal data"
        );
    }
}

#[test]
fn junk_git_queries_do_not_inherit_a_foreign_repository_authority() {
    let fixture = TempDir::new().unwrap();
    let base = git_fixture_root(&fixture);
    let root = base.join("own");
    let foreign = base.join("foreign");
    for directory in [&root, &foreign] {
        fs::create_dir_all(directory.join("target")).unwrap();
        let init = std::process::Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(directory)
            .status()
            .unwrap();
        assert!(init.success());
    }
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    fs::write(foreign.join("target/tracked"), b"foreign-data").unwrap();
    let add = std::process::Command::new("git")
        .arg("-C")
        .arg(&foreign)
        .args(["add", "--force", "target/tracked"])
        .status()
        .unwrap();
    assert!(add.success());
    let mut command = cli_command();
    let output = command
        .env("GIT_DIR", foreign.join(".git"))
        .env("GIT_WORK_TREE", &foreign)
        .args(["--format", "json", "junk"])
        .arg(&root)
        .timeout(std::time::Duration::from_secs(15))
        .assert()
        .success()
        .get_output()
        .clone();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["candidateCount"], 1);
    assert_eq!(report["candidates"][0]["confidence"], "high");
    assert_eq!(report["candidates"][0]["git"]["status"], "ignored");
    assert_eq!(
        report["candidates"][0]["blockers"],
        json!([
            "project_ownership_not_verified",
            "project_activity_not_verified"
        ])
    );
}

#[test]
fn junk_gitfile_boundaries_are_retained_in_classified_scans() {
    let fixture = TempDir::new().unwrap();
    let root = git_fixture_root(&fixture);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join(".git"), b"gitdir: unavailable-worktree\n").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    let mut command = cli_command();
    let output = command
        .args(["--format", "json", "junk"])
        .arg(&root)
        .timeout(std::time::Duration::from_secs(15))
        .assert()
        .success()
        .get_output()
        .clone();
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["candidateCount"], 1);
    assert_eq!(report["candidates"][0]["confidence"], "medium");
    assert_eq!(report["candidates"][0]["git"], Value::Null);
    assert_eq!(
        report["candidates"][0]["blockers"],
        json!([
            "project_ownership_not_verified",
            "project_activity_not_verified",
            "gitfile_repository_boundary"
        ])
    );
}

#[test]
fn junk_scan_strengthens_known_candidates_with_git_ignore_evidence() {
    let fixture = TempDir::new().unwrap();
    let root = git_fixture_root(&fixture);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    let status = std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(&root)
        .status()
        .unwrap();
    assert!(status.success());

    let mut cmd = cli_command();
    cmd.arg("--format").arg("json").arg("junk").arg(&root);
    let output = cmd.assert().get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let target = json["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["ruleId"] == "rust.target")
        .unwrap();

    assert_eq!(target["classification"], "known_generated_ignored");
    assert_eq!(target["confidence"], "high");
    assert_eq!(target["git"]["status"], "ignored");
    assert_eq!(target["git"]["check"], "git.check-ignore.v1");
    assert!(target["git"]["repositoryEntryId"].is_string());
    assert_eq!(
        target["blockers"],
        json!([
            "project_ownership_not_verified",
            "project_activity_not_verified"
        ])
    );
}

#[test]
fn junk_scan_does_not_promote_a_pattern_matching_tracked_directory() {
    let fixture = TempDir::new().unwrap();
    let root = git_fixture_root(&fixture);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join("target/tracked.txt"), b"keep").unwrap();
    let init = std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(&root)
        .status()
        .unwrap();
    assert!(init.success());
    let add = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .arg("add")
        .arg("--force")
        .arg("target/tracked.txt")
        .status()
        .unwrap();
    assert!(add.success());

    let mut cmd = cli_command();
    cmd.arg("--format").arg("json").arg("junk").arg(&root);
    let output = cmd.assert().get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let target = json["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["ruleId"] == "rust.target")
        .unwrap();

    assert_eq!(target["classification"], "known_generated");
    assert_eq!(target["confidence"], "medium");
    assert_eq!(target["git"], Value::Null);
    assert_eq!(
        target["blockers"],
        json!([
            "project_ownership_not_verified",
            "project_activity_not_verified",
            "tracked_descendant"
        ])
    );
}

#[test]
fn junk_scan_keeps_known_candidate_when_git_is_unavailable() {
    let fixture = TempDir::new().unwrap();
    let root = git_fixture_root(&fixture);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    fs::create_dir(root.join("target")).unwrap();
    let init = std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(&root)
        .status()
        .unwrap();
    assert!(init.success());
    let empty_path = root.join("empty-path");
    fs::create_dir(&empty_path).unwrap();

    let mut cmd = cli_command();
    cmd.env("PATH", empty_path)
        .arg("--format")
        .arg("json")
        .arg("junk")
        .arg(&root);
    let output = cmd.assert().get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let target = json["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["ruleId"] == "rust.target")
        .unwrap();

    assert_eq!(target["classification"], "known_generated");
    assert_eq!(target["confidence"], "medium");
    assert_eq!(target["git"], Value::Null);
    assert_eq!(
        target["blockers"],
        json!([
            "project_ownership_not_verified",
            "project_activity_not_verified",
            "git_query_failed"
        ])
    );
}

#[test]
fn junk_scan_does_not_promote_a_known_directory_containing_a_nested_repository() {
    let fixture = TempDir::new().unwrap();
    let root = git_fixture_root(&fixture);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    fs::create_dir_all(root.join("target/project/.git")).unwrap();
    let init = std::process::Command::new("git")
        .arg("init")
        .arg("--quiet")
        .arg(&root)
        .status()
        .unwrap();
    assert!(init.success());

    let mut cmd = cli_command();
    cmd.arg("--format").arg("json").arg("junk").arg(&root);
    let output = cmd.assert().get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let target = json["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["ruleId"] == "rust.target")
        .unwrap();

    assert_eq!(target["classification"], "known_generated");
    assert_eq!(target["confidence"], "medium");
    assert_eq!(target["git"], Value::Null);
    assert_eq!(
        target["blockers"],
        json!([
            "project_ownership_not_verified",
            "project_activity_not_verified",
            "nested_repository"
        ])
    );
}

#[cfg(target_os = "linux")]
#[test]
fn junk_system_uses_only_the_explicit_xdg_cache_root_and_reports_verification() {
    let _linux_temp_env = isolate_linux_temp_env();
    let fixture = TempDir::new().unwrap();
    let cache = fixture.path().join("cache");
    let home = fixture.path().join("home");
    let empty_path = fixture.path().join("empty-path");
    fs::create_dir_all(cache.join("example")).unwrap();
    fs::create_dir(&home).unwrap();
    fs::create_dir(&empty_path).unwrap();
    fs::write(cache.join("example/blob"), b"cache").unwrap();

    let mut cmd = cli_command();
    // `junk --system` intentionally discovers caches reported by installed tools in addition to
    // XDG. Isolate both HOME and PATH so a developer's real npm/pnpm/pip installation cannot add
    // unrelated candidates to this XDG-specific contract test.
    cmd.env("HOME", &home)
        .env("PATH", &empty_path)
        .env("XDG_CACHE_HOME", &cache)
        .env("SWEEPX_TEST_LINUX_TMP_ROOT", &empty_path)
        .arg("--format")
        .arg("json")
        .arg("junk")
        .arg("--system");
    let output = cmd.assert().get_output().clone();
    if output.stdout.is_empty() {
        panic!(
            "temp junk scan produced no JSON; exit={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let candidates = json["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["ruleId"], "linux.xdg-user-cache");
    assert_eq!(
        candidates[0]["path"],
        cache.join("example").display().to_string()
    );
    assert_eq!(candidates[0]["sourceReviewedAt"], "2026-08-29");
    assert_eq!(candidates[0]["risk"], "R2");
}

#[cfg(target_os = "linux")]
#[test]
fn junk_system_reports_old_arbitrary_temp_files_and_directories() {
    use std::os::unix::fs::PermissionsExt;

    let _linux_temp_env = isolate_linux_temp_env();
    let fixture = TempDir::new().unwrap();
    let temp_root = resolved_fixture_root(&fixture);
    let support = TempDir::new().unwrap();
    let old_dir = temp_root.join("arbitrary-old-directory");
    let old_file = temp_root.join("arbitrary-old-file");
    let old_symlink = temp_root.join("arbitrary-old-symlink");
    let old_fifo = temp_root.join("arbitrary-old-fifo");
    let active_dir = temp_root.join("arbitrary-active-directory");
    fs::create_dir(&old_dir).unwrap();
    fs::write(old_dir.join("payload"), b"cache").unwrap();
    fs::write(&old_file, b"old").unwrap();
    std::os::unix::fs::symlink("missing-target", &old_symlink).unwrap();
    let mkfifo = std::process::Command::new("mkfifo")
        .arg(&old_fifo)
        .status()
        .unwrap();
    assert!(mkfifo.success());
    fs::create_dir(&active_dir).unwrap();
    let touched = std::process::Command::new("touch")
        .arg("-d")
        .arg("@1600000000")
        .arg(&old_dir)
        .arg(old_dir.join("payload"))
        .arg(&old_file)
        .arg("-h")
        .arg(&old_symlink)
        .arg(&old_fifo)
        .arg(&active_dir)
        .status()
        .unwrap();
    assert!(touched.success());
    fs::write(active_dir.join("payload"), b"active").unwrap();
    let active_touched = std::process::Command::new("touch")
        .arg("-d")
        .arg("@4000000000")
        .arg(active_dir.join("payload"))
        .status()
        .unwrap();
    assert!(active_touched.success());
    fs::set_permissions(&temp_root, fs::Permissions::from_mode(0o700)).unwrap();
    let home = support.path().join("home");
    let empty_path = support.path().join("empty-path");
    let cache = support.path().join("cache");
    let tools = support.path().join("tools");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&empty_path).unwrap();
    fs::create_dir(&cache).unwrap();
    fs::create_dir(cache.join("empty")).unwrap();
    fs::create_dir(&tools).unwrap();
    std::os::unix::fs::symlink("/usr/bin/du", tools.join("du")).unwrap();

    let mut cmd = cli_command();
    cmd.env("HOME", &home)
        .env("PATH", &tools)
        .env("XDG_CACHE_HOME", &cache)
        .env("SWEEPX_TEST_LINUX_TMP_ROOT", &temp_root)
        .arg("--format")
        .arg("json")
        .arg("junk")
        .arg("--system");
    let output = cmd.assert().get_output().clone();
    assert!(
        !output.stdout.is_empty(),
        "target temp test produced no JSON; exit={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let candidates = json["candidates"].as_array().unwrap();
    let temp_candidates = candidates
        .iter()
        .filter(|candidate| candidate["ruleId"] == "linux.stale-temp-object")
        .collect::<Vec<_>>();
    assert_eq!(
        temp_candidates.len(),
        4,
        "temp discovery: {:?}; paths: {:?}",
        json["tempDiscovery"],
        temp_candidates
            .iter()
            .map(|candidate| candidate["path"].as_str())
            .collect::<Vec<_>>()
    );
    let paths = temp_candidates
        .iter()
        .map(|candidate| candidate["path"].as_str().unwrap().to_string())
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        old_dir.display().to_string(),
        old_file.display().to_string(),
        old_symlink.display().to_string(),
        old_fifo.display().to_string(),
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(paths, expected);
    assert_eq!(temp_candidates[0]["risk"], "R3");
    assert_eq!(json["tempDiscovery"]["complete"], true);
    assert_eq!(temp_candidates[0]["classification"], "stale_temp_report");
    assert_eq!(
        temp_candidates[0]["blockers"],
        json!(["system_wide_reference_view_unavailable"])
    );
}

#[cfg(target_os = "linux")]
#[test]
fn junk_system_accepts_an_explicit_direct_tmp_child_without_name_filter() {
    use std::os::unix::fs::PermissionsExt;

    let _linux_temp_env = isolate_linux_temp_env();
    let fixture = TempDir::new().unwrap();
    let temp_root = resolved_fixture_root(&fixture);
    let target = temp_root.join("anything-not-prefixed");
    fs::write(&target, b"old").unwrap();
    let touched = std::process::Command::new("touch")
        .arg("-d")
        .arg("@1600000000")
        .arg(&target)
        .status()
        .unwrap();
    assert!(touched.success());
    fs::set_permissions(&temp_root, fs::Permissions::from_mode(0o700)).unwrap();
    let home = temp_root.join("home");
    let empty_path = temp_root.join("empty-path");
    let cache = temp_root.join("cache");
    let tools = temp_root.join("tools");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&empty_path).unwrap();
    fs::create_dir(&cache).unwrap();
    fs::create_dir(&tools).unwrap();

    let mut cmd = cli_command();
    cmd.env("HOME", &home)
        .env("PATH", &empty_path)
        .env("XDG_CACHE_HOME", &cache)
        .env("SWEEPX_TEST_LINUX_TMP_ROOT", &temp_root)
        .arg("--format")
        .arg("json")
        .arg("junk")
        .arg("--system")
        .arg(&target);
    let output = cmd.assert().get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "no JSON; exit={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let paths = json["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| candidate["path"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(paths.contains(target.display().to_string().as_str()));
}

#[test]
fn junk_system_rejects_an_explicit_root_before_scanning() {
    let mut cmd = cli_command();
    cmd.arg("junk")
        .arg("--system")
        .arg("/definitely/not/a/tmp/child");
    cmd.assert().code(2);
}

#[test]
fn cargo_detect_rejects_cargo_passthrough_overrides_at_the_cli_boundary() {
    for args in [
        vec![
            "cleaner",
            "cargo-detect",
            "--target-dir",
            "/tmp/sweepx-forbidden-target",
            "/tmp/sweepx-workspace",
        ],
        vec![
            "cleaner",
            "cargo-detect",
            "--config",
            "build.target-dir='/tmp/sweepx-forbidden-target'",
            "/tmp/sweepx-workspace",
        ],
    ] {
        let mut cmd = cli_command();
        cmd.current_dir(cli_crate_dir()).args(args);

        let output = cmd.assert().code(2).get_output().clone();
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("unexpected argument"));
    }
}

#[cfg(unix)]
#[test]
fn cache_status_json_reports_absent_without_creating_default_state_dir() {
    let fixture = TempDir::new().unwrap();
    let home = resolved_fixture_root(&fixture).join("home");
    fs::create_dir(&home).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("HOME", &home)
        .env_remove("XDG_STATE_HOME")
        .arg("--format")
        .arg("json")
        .arg("cache")
        .arg("status");

    let output = cmd.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["kind"], "cache.status.result");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["summary"]["command"], "cache.status");
    assert_eq!(json["data"]["command"], "cache.status");
    assert_eq!(json["data"]["disposition"], "absent");
    assert_eq!(json["data"]["exists"], false);
    assert_eq!(json["data"]["currentGeneration"], Value::Null);
    assert_eq!(json["data"]["storedSchema"], Value::Null);
    assert_eq!(json["data"]["generationCount"], "0");
    assert_eq!(json["data"]["quarantineCount"], "0");
    assert_eq!(json["data"]["approxBytesComplete"], true);
    assert_eq!(
        sorted_object_keys(&json["data"]),
        [
            "approxBytes",
            "approxBytesComplete",
            "command",
            "currentGeneration",
            "currentHealth",
            "disposition",
            "errors",
            "exists",
            "generationCount",
            "quarantineCount",
            "schemaHealth",
            "storedSchema",
            "warnings",
        ]
    );
    assert!(json["data"].get("stateDir").is_none());
    assert!(json["data"].get("previewRoot").is_none());
    assert!(json["data"].get("parents").is_none());
    assert!(json["data"].get("entries").is_none());
    assert_eq!(json["data"]["warnings"], Value::Array(Vec::new()));
    assert_eq!(json["data"]["errors"], Value::Array(Vec::new()));
    assert!(!home.join(".local/state/sweepx").exists());
}

#[cfg(unix)]
#[test]
fn cache_status_does_not_create_explicit_state_or_preview_dirs() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["data"]["disposition"], "absent");
    assert!(!state_dir.exists());
}

#[cfg(unix)]
#[test]
fn cache_status_ndjson_is_usage_error_before_state_creation() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().code(2).get_output().clone();
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cache.status.result");
    assert_eq!(json["exitCode"], 2);
    assert_eq!(json["errors"][0]["code"], "cache.status.invalid_format");
    assert!(!state_dir.exists());
}

#[cfg(unix)]
#[test]
fn cache_status_json_reports_state_path_usage_errors_as_an_envelope() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg("relative-state")
        .arg("cache")
        .arg("status");

    let output = cmd.assert().code(2).get_output().clone();
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cache.status.result");
    assert_eq!(json["status"], "failed");
    assert_eq!(json["exitCode"], 2);
    assert_eq!(json["errors"][0]["code"], "cache.status.invalid_state_dir");
    assert!(
        !json["errors"][0]["params"]["detail"]
            .as_str()
            .unwrap()
            .contains("relative-state")
    );
}

#[cfg(unix)]
#[test]
fn cache_status_json_reports_insecure_cache_as_an_integrity_envelope() {
    let fixture = TempDir::new().unwrap();
    let fixture_root = resolved_fixture_root(&fixture);
    let state_dir = fixture_root.join("state");
    let preview_root = state_dir.join("preview-cache");
    fs::create_dir_all(&preview_root).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&preview_root, fs::Permissions::from_mode(0o755)).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().code(11).get_output().clone();
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cache.status.result");
    assert_eq!(json["status"], "failed");
    assert_eq!(json["exitCode"], 11);
    assert_eq!(json["errors"][0]["code"], "cache.status.inspection_failed");
    assert!(
        !json["errors"][0]["params"]["detail"]
            .as_str()
            .unwrap()
            .contains(fixture_root.to_string_lossy().as_ref())
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cache_status_json_reports_available_for_valid_preview_cache() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");
    let preview_root = state_dir.join("preview-cache");
    fs::create_dir_all(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let store = sweepx_cache::AtomicGenerationStore::new(&preview_root);
    store
        .write_generation(&sweepx_cache::StoredGeneration {
            generation: "gen_a".to_string(),
            schema: sweepx_cache::STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-28T00:00:00Z".to_string(),
            preview: sweepx_cache::CompactedPreview {
                parents: Default::default(),
                total_estimated_bytes: 0,
                total_records: 0,
                visible_resource_limit: false,
            },
            // No evidence: this test is about cache *status* reporting, not reuse. An empty vec is
            // the fail-closed value — the generation is readable and reported, never reused.
            validity: Vec::new(),
        })
        .unwrap();
    fs::set_permissions(&preview_root, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["summary"]["command"], "cache.status");
    assert_eq!(json["data"]["disposition"], "available");
    assert_eq!(json["data"]["exists"], true);
    assert_eq!(json["data"]["currentGeneration"], "gen_a");
    assert_eq!(json["data"]["generationCount"], "1");
    assert_eq!(json["data"]["quarantineCount"], "0");
    assert_eq!(json["data"]["currentHealth"], "available");
    assert_eq!(json["data"]["schemaHealth"], "available");
    assert_eq!(json["data"]["storedSchema"], "sweepx.preview.cache/v1");
    assert_eq!(json["data"]["warnings"], Value::Array(Vec::new()));
    assert_eq!(json["data"]["errors"], Value::Array(Vec::new()));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cache_status_json_reports_degraded_for_invalid_current_pointer() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");
    let preview_root = state_dir.join("preview-cache");
    fs::create_dir_all(&preview_root).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&preview_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(preview_root.join("current.json"), b"{not-json").unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().code(4).get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "partial");
    assert_eq!(json["data"]["disposition"], "degraded");
    assert_eq!(json["data"]["exists"], true);
    assert_eq!(json["data"]["currentHealth"], "error");
    assert_eq!(json["data"]["schemaHealth"], "unknown");
    assert_eq!(json["data"]["warnings"], Value::Array(Vec::new()));
    assert_eq!(
        json["data"]["errors"][0]["kind"],
        "malformed_current_pointer"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cache_status_quarantine_presence_is_degraded_and_read_only() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");
    let preview_root = state_dir.join("preview-cache");
    fs::create_dir_all(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let store = sweepx_cache::AtomicGenerationStore::new(&preview_root);
    store
        .write_generation(&sweepx_cache::StoredGeneration {
            generation: "gen_a".to_string(),
            schema: sweepx_cache::STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-28T00:00:00Z".to_string(),
            preview: sweepx_cache::CompactedPreview {
                parents: Default::default(),
                total_estimated_bytes: 0,
                total_records: 0,
                visible_resource_limit: false,
            },
            // See the note above: status reporting, not reuse, so no evidence is the right value.
            validity: Vec::new(),
        })
        .unwrap();
    let quarantine = preview_root.join("quarantine");
    fs::create_dir(&quarantine).unwrap();
    fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
    let quarantined = quarantine.join("old.corrupt.json");
    fs::write(&quarantined, b"broken").unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().code(4).get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["data"]["disposition"], "degraded");
    assert_eq!(json["data"]["quarantineCount"], "1");
    assert_eq!(json["data"]["warnings"][0]["kind"], "quarantine_present");
    assert_eq!(fs::read(&quarantined).unwrap(), b"broken");
}

#[cfg(unix)]
#[test]
fn cache_status_human_output_is_localized() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--locale")
        .arg("zh-CN")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().success().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("命令: cache.status"));
    assert!(text.contains("只读缓存诊断: absent"));
    assert!(!state_dir.exists());
}

#[cfg(unix)]
#[test]
fn cache_status_human_output_includes_degraded_reason() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");
    let preview_root = state_dir.join("preview-cache");
    fs::create_dir_all(&preview_root).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&preview_root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(preview_root.join("current.json"), b"{not-json").unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--locale")
        .arg("en-US")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");
    let output = cmd.assert().code(4).get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("Errors: cache.preview.inspect.malformed_current_pointer"));
}

#[cfg(unix)]
#[test]
fn cache_status_human_output_explains_empty_existing_cache() {
    let fixture = TempDir::new().unwrap();
    let state_dir = resolved_fixture_root(&fixture).join("state");
    let preview_root = state_dir.join("preview-cache");
    fs::create_dir_all(&preview_root).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&preview_root, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--locale")
        .arg("en-US")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");
    let output = cmd.assert().code(4).get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("exists=true"));
    assert!(text.contains("currentHealth=missing"));
    assert!(text.contains("schemaHealth=unknown"));
    assert!(text.contains("approxBytesComplete=true"));
}

/// Inspecting a cache that does not exist reports absence without creating it.
///
/// Replaces a test asserting the command was unsupported on Windows. The non-creating property is
/// the one worth keeping: a status query that created the directory it was asked about would make
/// "is there a cache here" impossible to answer, and would leave state behind on a read-only path.
#[cfg(target_os = "windows")]
#[test]
fn cache_status_reports_an_absent_cache_without_creating_state() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().success().get_output().clone();
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cache.status.result");
    assert_eq!(json["summary"]["exists"], false);
    assert_eq!(json["summary"]["currentHealth"], "missing");
    assert_eq!(json["errors"].as_array().map(Vec::len), Some(0));
    assert!(
        !state_dir.exists(),
        "inspection must never create the state directory"
    );
}

/// A cache written by a scan is then reported back by `cache status`.
///
/// Exercised through two separate CLI invocations so the reader and the writer are genuinely
/// different processes: a single in-process round trip could agree with itself through shared
/// state and prove nothing about what landed on disk.
#[cfg(target_os = "windows")]
#[test]
fn cache_status_reports_the_generation_a_scan_wrote() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let state_dir = fixture.path().join("state");

    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let scan_output = scan.assert().success().get_output().stdout.clone();
    let scan_json: Value = serde_json::from_slice(&scan_output).unwrap();
    let written = scan_json["summary"]["cachePreview"]["writtenGeneration"]
        .as_str()
        .expect("the scan must persist a generation")
        .to_string();

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");
    let status_output = status.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&status_output).unwrap();

    assert_eq!(json["summary"]["exists"], true);
    assert_eq!(json["summary"]["currentGeneration"], written);
    assert_eq!(json["summary"]["generationCount"], "1");
    assert_eq!(json["summary"]["quarantineCount"], "0");
    assert_eq!(json["errors"].as_array().map(Vec::len), Some(0));
}

/// A bad `--format` is rejected before any state directory work happens.
///
/// Renamed from "...precedes_platform_support": Windows is now a supported platform, so the
/// ordering that still matters is usage validation before filesystem access. A usage error must
/// not leave a state directory behind.
#[cfg(target_os = "windows")]
#[test]
fn cache_status_ndjson_usage_error_precedes_state_access() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("cache")
        .arg("status");

    let output = cmd.assert().code(2).get_output().clone();
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cache.status.result");
    assert_eq!(json["errors"][0]["code"], "cache.status.invalid_format");
    assert!(!state_dir.exists());
}

#[test]
fn old_public_tui_subcommand_is_removed() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("tui")
        .arg("--scan-json")
        .arg("/tmp/scan.json");
    cmd.assert().code(2);
}

#[test]
fn live_tui_rejects_json_before_validating_or_scanning_roots() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("scan")
        .arg("--tui")
        .arg("relative-root");
    let output = cmd.assert().code(2).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--tui cannot be combined"));
    assert!(!stderr.contains("scan root must be absolute"));
}

#[test]
fn live_tui_rejects_ndjson_as_an_invalid_tui_combination() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("scan")
        .arg("--tui")
        .arg("relative-root");
    let output = cmd.assert().code(2).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--tui cannot be combined"));
    assert!(!stderr.contains("durable event journal"));
    assert!(!stderr.contains("scan root must be absolute"));
}

#[test]
fn live_tui_rejects_non_terminal_streams_before_scanning() {
    let fixture = TempDir::new().unwrap();
    let missing_root = fixture.path().join("missing");
    let state_dir = fixture.path().join("state");
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg("--tui")
        .arg(&missing_root);
    let output = cmd.assert().code(2).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("requires terminal stdin and stdout"));
    assert!(!state_dir.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn scan_defaults_to_a_human_readable_file_table() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("LANG", "en_US.UTF-8")
        .arg("scan")
        .arg("--no-state")
        .arg(&root);
    let output = cmd.assert().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();

    assert!(text.contains("Path"));
    assert!(text.contains("Reclaimable"));
    assert!(text.contains("visible.txt"));
    assert!(text.contains("Summary: 1 roots, 1 entries"));
    assert!(text.contains("0 boundaries, 0 errors"));
    assert!(!text.trim_start().starts_with('{'));
}

#[cfg(target_os = "linux")]
#[test]
fn no_state_scan_skips_default_state_directory() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let state_home = fixture.path().join("state-home");

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("XDG_STATE_HOME", &state_home)
        .arg("--format")
        .arg("json")
        .arg("scan")
        .arg("--no-state")
        .arg(&root);
    cmd.assert().success();

    assert!(!state_home.exists());
}

#[cfg(unix)]
#[test]
fn missing_default_state_environment_fails_closed_without_explicit_opt_out() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env_remove("XDG_STATE_HOME")
        .env_remove("HOME")
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().code(2).get_output().clone();
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("no default state directory is available")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn no_state_scan_skips_an_unsafe_default_state_path() {
    use std::os::unix::fs::symlink;

    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let redirected_state_home = fixture.path().join("redirected-state-home");
    fs::create_dir(&redirected_state_home).unwrap();
    let unsafe_state_home = fixture.path().join("state-home");
    symlink(&redirected_state_home, &unsafe_state_home).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("XDG_STATE_HOME", &unsafe_state_home)
        .arg("--format")
        .arg("json")
        .arg("scan")
        .arg("--no-state")
        .arg(&root);
    cmd.assert().success();

    assert!(!redirected_state_home.join("sweepx").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn default_state_symlink_ancestor_fails_before_creating_redirected_state() {
    use std::os::unix::fs::symlink;

    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let redirected_state_home = fixture.path().join("redirected-state-home");
    fs::create_dir(&redirected_state_home).unwrap();
    let unsafe_state_home = fixture.path().join("state-home");
    symlink(&redirected_state_home, &unsafe_state_home).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("XDG_STATE_HOME", &unsafe_state_home)
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().code(2).get_output().clone();
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("must not be a symlink")
    );
    assert!(!redirected_state_home.join("sweepx").exists());
}

#[test]
fn no_state_conflicts_with_explicit_state_directory() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg("--no-state")
        .arg(fixture.path());
    let output = cmd.assert().code(2).get_output().clone();
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "failed");
    assert_eq!(json["exitCode"], 2);
    assert_eq!(json["errors"][0]["code"], "cli.conflicting_state_options");
    assert_eq!(
        json["errors"][0]["params"]["detail"],
        "--no-state cannot be combined with --state-dir"
    );
    assert!(!state_dir.exists());
}

/// Without `--state-dir`, Windows now defaults into `%LOCALAPPDATA%` and persists there.
///
/// The previous version of this test asserted that no durable state was created at all, which was
/// a statement about the missing security enforcement rather than a desired property. What must
/// stay true is that the default lands under LOCALAPPDATA and not in the Unix-style location.
#[cfg(target_os = "windows")]
#[test]
fn windows_scan_defaults_durable_state_into_local_appdata() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let user_profile = fixture.path().join("profile");
    let local_appdata = fixture.path().join("local-appdata");
    fs::create_dir(&user_profile).unwrap();
    fs::create_dir(&local_appdata).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("USERPROFILE", &user_profile)
        .env("LOCALAPPDATA", &local_appdata)
        .env_remove("XDG_STATE_HOME")
        .arg("--format")
        .arg("json")
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();

    assert_ne!(json["status"], "unsupported");
    assert_eq!(json["summary"]["platform"], "windows");
    assert_eq!(json["summary"]["cachePreview"]["storeStatus"], "written");
    assert!(
        json["data"]["entries"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| {
                entry["displayPath"]
                    .as_str()
                    .is_some_and(|path| path.ends_with("visible.txt"))
            }))
    );
    assert!(
        local_appdata.join("sweepx").join("state").is_dir(),
        "the default state directory must live under LOCALAPPDATA"
    );
    assert!(
        !user_profile.join(".local/state/sweepx").exists(),
        "the Unix location must never be used on Windows"
    );
}

/// An explicit `--state-dir` is accepted on Windows and the cache survives between runs.
///
/// This is the behavior the durable-state work exists to deliver, so it is asserted through the
/// real binary: the first run writes a generation and the second loads that same generation back.
#[cfg(target_os = "windows")]
#[test]
fn windows_explicit_state_dir_persists_between_runs() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let state_dir = fixture.path().join("state");

    let run = || {
        let mut cmd = cli_command();
        cmd.current_dir(cli_crate_dir())
            .arg("--format")
            .arg("json")
            .arg("--state-dir")
            .arg(&state_dir)
            .arg("scan")
            .arg(&root);
        let output = cmd.assert().success().get_output().stdout.clone();
        serde_json::from_slice::<Value>(&output).unwrap()
    };

    let first = run();
    assert_eq!(first["summary"]["cachePreview"]["loadStatus"], "miss");
    assert_eq!(first["summary"]["cachePreview"]["storeStatus"], "written");
    let written = first["summary"]["cachePreview"]["writtenGeneration"]
        .as_str()
        .expect("a generation id must be recorded when a preview is written")
        .to_string();
    assert!(state_dir.is_dir());

    let second = run();
    assert_eq!(
        second["summary"]["cachePreview"]["loadStatus"], "stale_preview",
        "a second run must find the generation the first one wrote"
    );
    assert_eq!(
        second["summary"]["cachePreview"]["loadedGeneration"], written,
        "the generation loaded must be exactly the one persisted"
    );
}

/// A state directory reachable by other users must be refused rather than silently used.
///
/// This is the guard that makes enabling durable state on Windows defensible, so it is exercised
/// against a directory widened through the OS's own tool, the same way a real misconfiguration
/// would arise.
#[cfg(target_os = "windows")]
#[test]
fn windows_refuses_a_state_dir_that_other_users_can_reach() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let state_dir = fixture.path().join("shared-state");
    fs::create_dir(&state_dir).unwrap();

    let granted = std::process::Command::new("icacls")
        .arg(&state_dir)
        .arg("/grant")
        .arg("*S-1-1-0:(OI)(CI)F")
        .output()
        .expect("icacls runs");
    assert!(granted.status.success());

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().failure().get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("accessible only to them"),
        "unexpected refusal message: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn default_human_scan_sanitizes_terminal_controls_in_paths() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("evil\u{1b}[31mred.txt"), b"data").unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("LANG", "en_US.UTF-8")
        .arg("--state-dir")
        .arg(fixture.path().join("state"))
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().success().get_output().stdout.clone();
    let text = String::from_utf8(output).unwrap();

    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("evil�[31mred.txt"));
}

#[cfg(target_os = "linux")]
#[test]
fn default_scan_table_is_bounded() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    for index in 0..45 {
        fs::write(root.join(format!("file-{index:02}.txt")), b"data").unwrap();
    }

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("LANG", "en_US.UTF-8")
        .arg("--state-dir")
        .arg(fixture.path().join("state"))
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().success().get_output().clone();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("Status: ok"));
    assert!(stdout.contains("more rows omitted"));
    assert!(stdout.lines().count() < 50);
}

#[cfg(unix)]
#[test]
fn explain_does_not_create_default_state_dir() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    let home = fixture.path().join("home");
    fs::create_dir(&home).unwrap();
    fs::write(&scan_json, sample_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("HOME", &home)
        .env_remove("XDG_STATE_HOME")
        .arg("explain")
        .arg("--scan-json")
        .arg(&scan_json);

    let _ = cmd.assert();
    assert!(!home.join(".local/state/sweepx").exists());
}

#[test]
fn capabilities_does_not_create_explicit_state_dir() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("capabilities");

    let _ = cmd.assert();
    assert!(!state_dir.exists());
}

#[cfg(unix)]
#[test]
fn scan_ndjson_is_rejected_before_state_creation_or_root_validation() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg("relative-root");

    let output = cmd.assert().code(3).get_output().clone();
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("disabled until SweepX has a runtime-qualified live event stream"));
    assert!(!stderr.contains("scan root must be absolute"));
    assert!(!state_dir.exists());
}

#[test]
fn status_watch_after_requires_watch() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("status")
        .arg("--operation-id")
        .arg("op-1")
        .arg("--after")
        .arg("sxcur1.invalid-token");

    let output = cmd.assert().code(2).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--after requires --watch"));
}

#[test]
fn status_watch_requires_ndjson() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("status")
        .arg("--operation-id")
        .arg("op-1")
        .arg("--watch");

    let output = cmd.assert().code(2).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--watch requires --format ndjson"));
}

#[cfg(target_os = "linux")]
#[test]
fn status_watch_replays_completed_journal_events() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("alpha.txt"), b"alpha").unwrap();
    let state_dir = fixture.path().join("state");

    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let scan_stdout = scan.assert().success().get_output().stdout.clone();
    let scan_json: Value = serde_json::from_slice(&scan_stdout).unwrap();
    let operation_id = scan_json["operationId"].as_str().unwrap().to_string();

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(&operation_id)
        .arg("--watch");
    let output = status.assert().success().get_output().clone();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let events = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert!(!events.is_empty());
    assert_eq!(events.last().unwrap()["type"], "operation.terminal");
    assert!(
        events.last().unwrap()["payload"]["snapshotDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let resume_cursor = events.first().unwrap()["cursor"]
        .as_str()
        .unwrap()
        .to_string();
    let mut resumed = cli_command();
    resumed
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(&operation_id)
        .arg("--watch")
        .arg("--after")
        .arg(&resume_cursor);
    let resumed_stdout = resumed.assert().success().get_output().stdout.clone();
    let resumed_events = String::from_utf8(resumed_stdout)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(resumed_events, events[1..]);

    let terminal_cursor = events.last().unwrap()["cursor"].as_str().unwrap();
    let mut exhausted = cli_command();
    exhausted
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(&operation_id)
        .arg("--watch")
        .arg("--after")
        .arg(terminal_cursor);
    exhausted.assert().success().stdout("");
}

#[cfg(target_os = "linux")]
#[test]
fn status_watch_unknown_cursor_emits_one_reset_control() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("alpha.txt"), b"alpha").unwrap();
    let state_dir = fixture.path().join("state");

    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let scan_stdout = scan.assert().success().get_output().stdout.clone();
    let scan_json: Value = serde_json::from_slice(&scan_stdout).unwrap();
    let operation_id = scan_json["operationId"].as_str().unwrap();

    let mut full_replay = cli_command();
    full_replay
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(operation_id)
        .arg("--watch");
    let full_stdout = full_replay.assert().success().get_output().stdout.clone();
    let expected_high_water = String::from_utf8(full_stdout)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .next_back()
        .unwrap()["cursor"]
        .as_str()
        .unwrap()
        .to_string();

    let requested = "sxcur1.unknown-generation-token-0001";
    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(operation_id)
        .arg("--watch")
        .arg("--after")
        .arg(requested);
    let stdout = status.assert().success().get_output().stdout.clone();
    let lines = String::from_utf8(stdout).unwrap();
    let events = lines
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    let reset = &events[0];
    assert_eq!(reset["type"], "stream.reset_required");
    assert_eq!(reset["terminal"], false);
    assert_eq!(reset["payload"]["requestedCursor"], requested);
    assert_eq!(reset["payload"]["availableFromSequence"], "1");
    assert_eq!(reset["payload"]["snapshotRef"]["operationId"], operation_id);
    assert!(
        reset["payload"]["resumeAfter"]
            .as_str()
            .unwrap()
            .starts_with("sxcur1.")
    );
    assert_eq!(reset["payload"]["resumeAfter"], expected_high_water);
}

#[cfg(target_os = "linux")]
#[test]
fn status_watch_with_malformed_cursor_exits_usage_error() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("alpha.txt"), b"alpha").unwrap();
    let state_dir = fixture.path().join("state");

    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let scan_stdout = scan.assert().success().get_output().stdout.clone();
    let scan_json: Value = serde_json::from_slice(&scan_stdout).unwrap();
    let operation_id = scan_json["operationId"].as_str().unwrap().to_string();

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(&operation_id)
        .arg("--watch")
        .arg("--after")
        .arg("not-a-durable-cursor");

    let output = status.assert().code(2).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid replay cursor"));
}

#[cfg(target_os = "linux")]
#[test]
fn status_watch_missing_operation_returns_not_found() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg("op-missing")
        .arg("--watch");
    let output = status.assert().code(8).get_output().clone();
    assert!(output.stdout.is_empty());
    assert!(!state_dir.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn status_watch_missing_operation_does_not_create_legacy_directory() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");
    fs::create_dir(&state_dir).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg("op-missing")
        .arg("--watch");
    let output = status.assert().code(8).get_output().clone();
    assert!(output.stdout.is_empty());
    assert!(!state_dir.join("operations").exists());
    assert!(!state_dir.join("event-journals").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn status_watch_legacy_only_snapshot_is_unsupported() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("alpha.txt"), b"alpha").unwrap();
    let state_dir = fixture.path().join("state");
    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let scan_stdout = scan.assert().success().get_output().stdout.clone();
    let scan_json: Value = serde_json::from_slice(&scan_stdout).unwrap();
    let operation_id = scan_json["operationId"].as_str().unwrap().to_string();
    let journal_dir = only_child_directory(&state_dir.join("event-journals"));
    let digest = journal_dir
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    fs::remove_dir_all(&journal_dir).unwrap();

    let operations = state_dir.join("operations");
    fs::create_dir_all(&operations).unwrap();
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&operations, fs::Permissions::from_mode(0o700)).unwrap();
    let legacy_path = operations.join(format!("{digest}.json"));
    fs::write(
        &legacy_path,
        serde_json::to_vec(&json!({
            "schema": "sweepx.operation-snapshot/v1",
            "operationId": operation_id,
            "requestId": "legacy-request",
            "command": "scan",
            "state": "completed",
            "status": "ok",
            "exitCode": 0,
            "createdAt": "2026-08-28T00:00:00Z",
            "updatedAt": "2026-08-28T00:00:00Z",
            "locale": "en-US",
            "rootPaths": [],
            "scanId": null,
            "terminalEventType": "operation.terminal",
            "entryCount": "0",
            "errorCount": "0",
            "boundaryCount": "0",
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o600)).unwrap();

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(&operation_id)
        .arg("--watch");
    status.assert().code(3);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn status_watch_is_unsupported_off_linux() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");
    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg("op-1")
        .arg("--watch");
    status.assert().code(3);
}

#[cfg(target_os = "linux")]
#[test]
fn scan_json_persists_snapshot_for_status_lookup() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("alpha.txt"), b"alpha").unwrap();
    let state_dir = fixture.path().join("state");

    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(root.as_os_str());
    let scan_stdout = scan.assert().get_output().stdout.clone();
    let scan_json: Value = serde_json::from_slice(&scan_stdout).unwrap();
    let operation_id = scan_json["operationId"].as_str().unwrap().to_string();
    let journal_dir = only_child_directory(&state_dir.join("event-journals"));
    assert!(journal_dir.join("journal.db").is_file());
    assert!(!state_dir.join("operations").exists());

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(&operation_id);
    let status_stdout = status.assert().get_output().stdout.clone();
    let status_json: Value = serde_json::from_slice(&status_stdout).unwrap();

    assert_eq!(status_json["kind"], "status.result");
    assert_eq!(status_json["summary"]["found"], true);
    assert_eq!(status_json["data"]["operationId"], operation_id);
    assert_eq!(status_json["data"]["command"], "scan");
    assert_eq!(status_json["data"]["canCancel"], false);
    assert_eq!(
        sorted_object_keys(&status_json["data"]),
        [
            "boundaryCount",
            "canCancel",
            "command",
            "createdAt",
            "entryCount",
            "errorCount",
            "locale",
            "operationId",
            "rootCount",
            "scanId",
            "state",
            "status",
            "terminalEventType",
            "updatedAt",
        ]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn corrupt_journal_does_not_fall_back_to_same_id_legacy_snapshot() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("alpha.txt"), b"alpha").unwrap();
    let state_dir = fixture.path().join("state");

    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let scan_stdout = scan.assert().success().get_output().stdout.clone();
    let scan_json: Value = serde_json::from_slice(&scan_stdout).unwrap();
    let operation_id = scan_json["operationId"].as_str().unwrap();
    let journal_dir = only_child_directory(&state_dir.join("event-journals"));
    let digest = journal_dir.file_name().unwrap().to_string_lossy();

    let operations = state_dir.join("operations");
    fs::create_dir(&operations).unwrap();
    fs::set_permissions(&operations, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        operations.join(format!("{digest}.json")),
        serde_json::to_vec(&json!({
            "schema": "sweepx.operation-snapshot/v1",
            "operationId": operation_id,
            "requestId": "legacy-request",
            "command": "scan",
            "state": "completed",
            "status": "ok",
            "exitCode": 0,
            "createdAt": "2026-08-28T00:00:00Z",
            "updatedAt": "2026-08-28T00:00:00Z",
            "locale": "en-US",
            "rootPaths": [],
            "scanId": null,
            "terminalEventType": "operation.terminal",
            "entryCount": "0",
            "errorCount": "0",
            "boundaryCount": "0",
            "error": null
        }))
        .unwrap(),
    )
    .unwrap();
    let journal = journal_dir.join("journal.db");
    let mut bytes = fs::read(&journal).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&journal, bytes).unwrap();

    let mut status = cli_command();
    status
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(operation_id);
    let output = status.assert().code(11).get_output().clone();
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("event journal failed")
    );

    let mut watch = cli_command();
    watch
        .current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("status")
        .arg("--operation-id")
        .arg(operation_id)
        .arg("--watch");
    let watch_output = watch.assert().code(11).get_output().clone();
    assert!(watch_output.stdout.is_empty());
    assert!(
        String::from_utf8(watch_output.stderr)
            .unwrap()
            .contains("event journal failed")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn duplicate_and_overlapping_roots_are_scanned_once() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    let child = root.join("child");
    fs::create_dir_all(&child).unwrap();
    fs::write(child.join("one.txt"), b"one").unwrap();

    let mut scan = cli_command();
    scan.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(fixture.path().join("state"))
        .arg("scan")
        .arg(&child)
        .arg(&root)
        .arg(&root);
    let output = scan.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(json["summary"]["rootCount"], "1");
    assert_eq!(json["data"]["roots"].as_array().unwrap().len(), 1);
    assert_eq!(
        json["data"]["roots"][0]["displayPath"],
        root.to_string_lossy().as_ref()
    );
    let paths = json["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["displayPath"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths
            .iter()
            .filter(|path| **path == child.join("one.txt").to_string_lossy())
            .count(),
        1
    );
}

#[test]
fn cancel_json_is_honest_for_missing_operation() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("cancel")
        .arg("--operation-id")
        .arg("op_missing_123");

    let output = cmd.assert().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["kind"], "cancel.result");
    assert_eq!(json["summary"]["disposition"], "not_found");
    assert_eq!(json["data"]["canCancel"], false);
    assert_eq!(json["data"]["operation"], Value::Null);
    assert_eq!(
        sorted_object_keys(&json["data"]),
        ["canCancel", "disposition", "operation", "operationId"]
    );
}

#[cfg(unix)]
#[test]
fn relative_state_dir_is_rejected() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--state-dir")
        .arg("relative")
        .arg("scan")
        .arg(root.as_os_str());
    let output = cmd.assert().get_output().stderr.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("state directory must be absolute"));
}

#[cfg(target_os = "linux")]
#[test]
fn symlink_boundary_does_not_force_partial_scan() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("file.txt"), b"1234").unwrap();
    std::os::unix::fs::symlink(root.join("file.txt"), root.join("file-link")).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(fixture.path().join("state"))
        .arg("scan")
        .arg(root.as_os_str());

    let stdout = cmd.assert().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(json["status"], "ok");
}

fn cli_crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sorted_object_keys(value: &Value) -> Vec<&str> {
    let mut keys = value
        .as_object()
        .expect("value must be an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

fn sample_scan_json() -> String {
    serde_json::to_string(&json!({
        "schema": "sweepx.output/v1",
        "kind": "scan.result",
        "requestId": "req-1",
        "operationId": "op-1",
        "generatedAt": "2026-08-26T00:00:00Z",
        "status": "ok",
        "exitCode": 0,
        "compat": {
            "coreVersion": "0.1.0",
            "scannerSemanticsVersion": 1,
            "safetyPolicyVersion": 1,
            "platformAdapter": {
                "id": "linux",
                "version": "0.1.0"
            },
            "cleanerSetDigest": "sha256:test",
            "requiredFeatures": [],
            "extensions": []
        },
        "summary": {
            "scanId": "scan-1"
        },
        "data": {
            "scanId": "scan-1",
            "roots": [],
            "entries": [{
                "scanId": "scan-1",
                "displayPath": "/tmp/demo",
                "nativeBasename": {
                    "kind": "unix_bytes_base64_url",
                    "value": "ZGVtbw"
                },
                "objectType": "directory",
                "logicalBytes": {
                    "state": "known",
                    "value": "42"
                },
                "allocatedBytes": {
                    "state": "known",
                    "value": "42"
                },
                "reclaimableEstimate": {
                    "state": "known",
                    "value": "42"
                },
                "metadataFingerprint": "fp-1",
                "coverage": {
                    "state": "complete",
                    "complete": true,
                    "incompleteReasons": [],
                    "detailsLost": false,
                    "provenance": {
                        "kind": "live_observation",
                        "observed_at": "2026-08-26T00:00:00Z",
                        "method": "native_api"
                    }
                },
                "provenance": {
                    "kind": "live_observation",
                    "observed_at": "2026-08-26T00:00:00Z",
                    "method": "native_api"
                }
            }],
            "aggregates": [{
                "scanId": "scan-1",
                "directoryIdentity": "/tmp/demo",
                "revision": "1",
                "apparentLogicalBytes": {
                    "state": "known",
                    "value": "42"
                },
                "uniqueLogicalBytes": {
                    "state": "known",
                    "value": "42"
                },
                "filesystemReportedAllocatedBytes": {
                    "state": "known",
                    "value": "42"
                },
                "potentiallyReclaimableBytes": {
                    "state": "known",
                    "value": "42"
                },
                "directChildCount": {
                    "state": "known",
                    "value": "1"
                },
                "recursiveEntryCount": {
                    "state": "known",
                    "value": "1"
                },
                "coverage": {
                    "state": "complete",
                    "complete": true,
                    "incompleteReasons": [],
                    "detailsLost": false,
                    "provenance": {
                        "kind": "live_observation",
                        "observed_at": "2026-08-26T00:00:00Z",
                        "method": "native_api"
                    }
                },
                "arithmeticState": "exact"
            }],
            "boundaries": []
        },
        "warnings": [],
        "errors": []
    }))
    .unwrap()
}

#[test]
fn junk_dart_formats_are_visible_and_nonterminal_trash_keeps_its_guard() {
    #[cfg(target_os = "linux")]
    let owner = TempDir::new_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = TempDir::new().unwrap();
    #[cfg(unix)]
    let root = resolved_fixture_root(&owner);
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    std::fs::create_dir(root.join(".dart_tool")).unwrap();
    std::fs::write(root.join("pubspec.yaml"), b"name: example\n").unwrap();
    let file = root.join(".dart_tool/package_config.json");
    for (body, status, classification, confidence) in [
        (
            r#"{"configVersion":2,"packages":[{"name":"example","rootUri":"../","packageUri":"lib/"}],"generator":"pub","generatorVersion":"3.6.0"}"#,
            "recognized",
            "recognized_generated_format",
            "medium",
        ),
        ("{invalid", "invalid", "project_layout", "low"),
        (
            r#"{"configVersion":3,"packages":[]}"#,
            "unknown",
            "project_layout",
            "low",
        ),
    ] {
        std::fs::write(&file, body).unwrap();
        for locale in ["en-US", "zh-CN"] {
            let output = cli_command()
                .timeout(std::time::Duration::from_secs(20))
                .args(["--locale", locale, "--format", "json", "junk"])
                .arg(&root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let json: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["candidates"].as_array().unwrap().len(), 1);
            let row = &json["candidates"][0];
            assert_eq!(row["projectFormat"]["status"], status);
            assert_eq!(
                row["projectFormat"]["profile"],
                "dart_pub_package_config_v2"
            );
            assert_eq!(row["classification"], classification);
            assert_eq!(row["confidence"], confidence);
            assert!(
                row["blockers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|b| b == "project_ownership_not_verified")
            );
            let refused = cli_command()
                .timeout(std::time::Duration::from_secs(20))
                .args(["--locale", locale, "junk", "--trash"])
                .arg(&root)
                .output()
                .unwrap();
            assert_eq!(refused.status.code(), Some(2));
            assert!(
                String::from_utf8_lossy(&refused.stderr)
                    .contains("foreground interactive terminal")
            );
            assert_eq!(std::fs::read(&file).unwrap(), body.as_bytes());
            // Content paths/values are not serialized through the format evidence object.
            assert_eq!(row["projectFormat"].as_object().unwrap().len(), 3);
        }
    }
}

#[test]
fn junk_legacy_sync_unknown_and_invalid_contents_keep_locale_stable_report_only_status() {
    use sweepx_fixtures::project_junk::{SVELTEKIT_AMBIENT, SVELTEKIT2_CONFIG};
    #[cfg(target_os = "linux")]
    let owner = TempDir::new_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = TempDir::new().unwrap();
    #[cfg(unix)]
    let root = resolved_fixture_root(&owner);
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    std::fs::create_dir(root.join(".svelte-kit")).unwrap();
    std::fs::write(root.join("svelte.config.js"), "export default {}\n").unwrap();
    let config_path = root.join(".svelte-kit/tsconfig.json");
    let ambient_path = root.join(".svelte-kit/ambient.d.ts");
    for (config, ambient, status) in [
        (SVELTEKIT2_CONFIG, SVELTEKIT_AMBIENT, "recognized"),
        ("{invalid", SVELTEKIT_AMBIENT, "invalid"),
        (
            SVELTEKIT2_CONFIG,
            "user source with no generated signatures",
            "unknown",
        ),
    ] {
        std::fs::write(&config_path, config).unwrap();
        std::fs::write(&ambient_path, ambient).unwrap();
        for locale in ["en-US", "zh-CN"] {
            let output = cli_command()
                .timeout(std::time::Duration::from_secs(20))
                .args(["--locale", locale, "--format", "json", "junk"])
                .arg(&root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["candidates"].as_array().unwrap().len(), 1);
            let row = &report["candidates"][0];
            assert_eq!(row["ruleId"], "node.sveltekit-output");
            assert_eq!(row["projectFormat"]["profile"], "svelte_kit_legacy_sync");
            assert_eq!(row["projectFormat"]["status"], status);
            assert_eq!(
                row["confidence"],
                if status == "recognized" {
                    "medium"
                } else {
                    "low"
                }
            );
            assert!(
                row["blockers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|b| b == "project_ownership_not_verified")
            );
            assert_eq!(row["projectFormat"].as_object().unwrap().len(), 3);
            assert_eq!(std::fs::read(&config_path).unwrap(), config.as_bytes());
            assert_eq!(std::fs::read(&ambient_path).unwrap(), ambient.as_bytes());
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn junk_system_reports_bounded_tool_discovery_in_both_locales() {
    let fixture = TempDir::new().unwrap();
    let root = resolved_fixture_root(&fixture);
    let home = root.join("home");
    let cache = home.join("Library/Caches/Homebrew");
    fs::create_dir_all(cache.join("downloads")).unwrap();
    let payload = cache.join("downloads/user-data");
    fs::write(&payload, b"unchanged discovery fixture").unwrap();
    // Oversized PATH is supplied only to each child. No process-global environment mutation,
    // tool execution or live user cache is required to exercise the production discovery gate.
    let oversized_path = "x".repeat(65_537);
    for locale in ["en-US", "zh-CN"] {
        let output = cli_command()
            .timeout(std::time::Duration::from_secs(15))
            .env("HOME", &home)
            .env("PATH", &oversized_path)
            .args(["--locale", locale, "--format", "json", "--state-dir"])
            .arg(root.join(format!("state-{locale}")))
            .args(["junk", "--system"])
            .assert()
            .code(4)
            .get_output()
            .clone();
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], "partial");
        assert_eq!(
            report["npmDiscovery"],
            json!({"complete": false, "incompleteReason": "resource_limit"})
        );
        assert_eq!(report["toolInstallations"], json!([]));
        assert!(
            report["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["ruleId"] == "macos.homebrew-cache"
                    && row["path"] == cache.display().to_string())
        );
    }
    assert_eq!(fs::read(payload).unwrap(), b"unchanged discovery fixture");
}
