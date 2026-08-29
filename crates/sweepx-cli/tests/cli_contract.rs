use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::{Value, json};
use sweepx_protocol::{
    CapabilityCell, CapabilityRecordV1, CapabilityState, EvidenceClass, OsFamily,
};
use tempfile::TempDir;

fn cli_command() -> Command {
    Command::cargo_bin("sweepx").expect("binary available")
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
    assert_eq!(json["summary"]["commandCount"], "10");
    assert_eq!(json["summary"]["capabilityCount"], "40");
    let commands = json["data"]["commands"].as_array().unwrap();
    assert_eq!(
        commands
            .iter()
            .filter(|command| command["mutating"] == true)
            .map(|command| command["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["trash"]
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
    let expected_cache_status_state = if cfg!(target_os = "windows") {
        "disabled"
    } else {
        "degraded"
    };
    assert_eq!(cache_status["state"], expected_cache_status_state);
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
        assert_eq!(cleaner["state"], "report_only");

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
        let expected_snapshot_state = if os == "windows" {
            "disabled"
        } else {
            "qualified"
        };
        assert_eq!(durable_snapshot["state"], expected_snapshot_state);
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
        assert_eq!(
            cache_preview["state"],
            if os == "windows" {
                "disabled"
            } else {
                "degraded"
            }
        );
        assert_eq!(
            cache_preview["reasonCode"],
            if os == "windows" {
                "CACHE_PREVIEW_INSPECTION_UNAVAILABLE"
            } else {
                "CACHE_PREVIEW_INSPECTION_READ_ONLY"
            }
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
    assert_eq!(json["status"], "partial");
    assert_eq!(
        json["data"]["cleaners"][0]["compatibility"]["state"],
        "compatible"
    );
}

#[test]
fn cleaner_show_reports_incompatible_builtin_with_exit_12() {
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("cleaner")
        .arg("show")
        .arg("org.sweepx.chromium-rebuildable-cache");

    let output = cmd.assert().code(12).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("cleaner is incompatible with this core"));
}

#[test]
fn experimental_cargo_detect_scans_with_compatible_builtin() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("workspace");
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
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cleaner.result");
    assert_eq!(json["summary"]["command"], "cleaner.cargo-detect");
    assert_eq!(json["summary"]["experimental"], true);
    assert_eq!(json["summary"]["liveOnly"], true);
    assert_eq!(json["summary"]["matchCount"], "0");
    assert_eq!(json["summary"]["hintCount"], "1");
    assert_eq!(json["data"]["readOnly"], true);
    assert_eq!(json["data"]["candidateAllowed"], false);
    assert_eq!(json["data"]["planAllowed"], false);
    assert_eq!(json["data"]["approvalAllowed"], false);
    assert_eq!(json["data"]["executionAllowed"], false);
    assert_eq!(json["data"]["builtinManifestCompatible"], true);
    assert_eq!(json["data"]["matchCount"], "0");
    assert_eq!(json["data"]["hintCount"], "1");
    assert_eq!(json["data"]["matches"], Value::Array(Vec::new()));
    assert_eq!(
        json["data"]["hints"][0]["displayPath"],
        root.join("target").display().to_string()
    );
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
fn trash_requires_confirmation_for_machine_invocations() {
    let fixture = TempDir::new().unwrap();
    let path = fixture.path().join("keep.txt");
    fs::write(&path, b"keep").unwrap();

    let mut cmd = cli_command();
    cmd.arg("--format").arg("json").arg("trash").arg(&path);
    let output = cmd.assert().code(8).get_output().clone();
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "failed");
    assert_eq!(json["permanentFallback"], false);
    assert!(path.exists());
}

#[test]
fn trash_rejects_relative_paths_without_changing_them() {
    let mut cmd = cli_command();
    cmd.arg("trash").arg("relative.txt");
    cmd.assert().code(8);
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
    let home = fixture.path().join("home");
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
    let state_dir = fixture.path().join("state");

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
    let state_dir = fixture.path().join("state");
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
            .contains(fixture.path().to_string_lossy().as_ref())
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cache_status_json_reports_available_for_valid_preview_cache() {
    let fixture = TempDir::new().unwrap();
    let state_dir = fixture.path().join("state");
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
    let state_dir = fixture.path().join("state");
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
    let state_dir = fixture.path().join("state");
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
    let state_dir = fixture.path().join("state");
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
    let state_dir = fixture.path().join("state");
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
    let state_dir = fixture.path().join("state");
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

#[cfg(target_os = "windows")]
#[test]
fn cache_status_is_unsupported_before_state_creation() {
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

    let output = cmd.assert().code(3).get_output().clone();
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["kind"], "cache.status.result");
    assert_eq!(json["exitCode"], 3);
    assert_eq!(
        json["errors"][0]["code"],
        "cache.status.unsupported_platform"
    );
    assert!(!state_dir.exists());
}

#[cfg(target_os = "windows")]
#[test]
fn cache_status_ndjson_usage_error_precedes_platform_support() {
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

#[cfg(target_os = "windows")]
#[test]
fn windows_scan_runs_without_creating_durable_state() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let user_profile = fixture.path().join("profile");
    fs::create_dir(&user_profile).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .env("USERPROFILE", &user_profile)
        .env_remove("XDG_STATE_HOME")
        .arg("--format")
        .arg("json")
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().success().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();

    assert_ne!(json["status"], "unsupported");
    assert_eq!(json["summary"]["platform"], "windows");
    assert_eq!(json["summary"]["cachePreview"]["loadStatus"], "miss");
    assert_eq!(json["summary"]["cachePreview"]["storeStatus"], "skipped");
    assert!(
        json["data"]["entries"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| {
                entry["displayPath"]
                    .as_str()
                    .is_some_and(|path| path.ends_with("visible.txt"))
            }))
    );
    assert!(!user_profile.join(".local/state/sweepx").exists());
}

#[cfg(target_os = "windows")]
#[test]
fn windows_explicit_state_dir_fails_before_scan_or_state_creation() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("visible.txt"), b"hello").unwrap();
    let state_dir = fixture.path().join("state");

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(&root);
    let output = cmd.assert().code(3).get_output().clone();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(stderr.contains("durable state is disabled on Windows"));
    assert!(!state_dir.exists());
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
