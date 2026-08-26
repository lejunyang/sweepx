use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;
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
    assert_eq!(json["data"]["commands"][0]["id"], "scan");
    assert_eq!(json["data"]["commands"][0]["state"], "degraded");
    assert_eq!(json["data"]["commands"][2]["id"], "cancel");
    assert_eq!(json["data"]["commands"][2]["state"], "disabled");
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
    let mut cmd = cli_command();
    cmd.current_dir(cli_crate_dir())
        .arg("--state-dir")
        .arg("relative")
        .arg("capabilities");
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
