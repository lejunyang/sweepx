use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;

fn cli_command() -> Command {
    Command::cargo_bin("sweepx").expect("binary available")
}

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
    assert_eq!(json["summary"]["capabilityCount"], "14");
    let commands = json["data"]["commands"].as_array().unwrap();
    let scan = commands.iter().find(|item| item["id"] == "scan").unwrap();
    assert_eq!(scan["state"], "degraded");
    let cancel = commands.iter().find(|item| item["id"] == "cancel").unwrap();
    assert_eq!(cancel["state"], "disabled");
    let explain = commands
        .iter()
        .find(|item| item["id"] == "explain")
        .unwrap();
    assert_eq!(explain["state"], "qualified");
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
                    && item["qualificationKey"]["capability"] == "tui.read.scan_json"
            })
            .unwrap();
        assert_eq!(tui["state"], "qualified");
    }
}

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
        "incompatible"
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
fn tui_read_json_reports_bounded_read_only_status() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    fs::write(&scan_json, sample_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("json")
        .arg("tui")
        .arg("--scan-json")
        .arg(&scan_json);

    let output = cmd.assert().get_output().stdout.clone();
    let json: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["kind"], "status.result");
    assert_eq!(json["summary"]["command"], "tui");
    assert_eq!(json["data"]["mode"], "read_only");
    assert_eq!(json["data"]["readOnly"], true);
}

#[test]
fn tui_rejects_zero_limits() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    fs::write(&scan_json, sample_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("tui")
        .arg("--scan-json")
        .arg(&scan_json)
        .arg("--max-total-rows")
        .arg("0");

    let output = cmd.assert().get_output().stderr.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("analysis input must be a positive bounded byte limit"));
}

#[test]
fn tui_rejects_invalid_kind_input() {
    let fixture = TempDir::new().unwrap();
    let scan_json = fixture.path().join("scan.json");
    fs::write(&scan_json, sample_non_scan_json()).unwrap();

    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("tui")
        .arg("--scan-json")
        .arg(&scan_json);

    let output = cmd.assert().get_output().stderr.clone();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("expected scan.result input"));
}

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

#[cfg(target_os = "linux")]
#[test]
fn scan_ndjson_ends_with_exactly_one_terminal_event_and_reports_symlink_boundary() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("file.txt"), b"1234").unwrap();
    let symlink_path = root.join("file-link");
    std::os::unix::fs::symlink(root.join("file.txt"), &symlink_path).unwrap();

    let state_dir = fixture.path().join("state");
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--format")
        .arg("ndjson")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("scan")
        .arg(root.as_os_str());

    let stdout = cmd.assert().get_output().stdout.clone();
    let text = String::from_utf8(stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines.is_empty());

    let events: Vec<Value> = lines
        .iter()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect();
    let terminal_count = events
        .iter()
        .filter(|event| event["type"] == "operation.terminal" && event["terminal"] == true)
        .count();
    assert_eq!(terminal_count, 1);
    assert_eq!(events.last().unwrap()["type"], "operation.terminal");
    assert_eq!(events.last().unwrap()["terminal"], true);
    assert_eq!(events.last().unwrap()["checkpoint"]["durable"], false);
    assert_eq!(
        events.last().unwrap()["checkpoint"]["lastDurableSequence"],
        "0"
    );

    let boundary = events.iter().find(|event| {
        event["type"] == "scan.boundary.observed" && event["payload"]["boundaryKind"] == "symlink"
    });
    assert!(boundary.is_some());

    let started = &events[0];
    assert_eq!(started["checkpoint"]["durable"], false);
    assert_eq!(started["payload"]["resumable"], false);
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

fn sample_non_scan_json() -> String {
    serde_json::to_string(&json!({
        "schema": "sweepx.output/v1",
        "kind": "capabilities.result",
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
        "summary": {},
        "data": {},
        "warnings": [],
        "errors": []
    }))
    .unwrap()
}
