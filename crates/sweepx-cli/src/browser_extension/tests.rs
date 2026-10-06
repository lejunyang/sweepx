use super::*;
use std::io::Cursor;

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    // macOS /var is linked; production authority deliberately rejects linked ancestors.
    #[cfg(unix)]
    let root = temp.path().canonicalize().unwrap().join("private");
    #[cfg(not(unix))]
    let root = temp.path().join("private");
    (temp, root)
}

fn plan() -> Value {
    json!({"schema":"sweepx.browser_cleanup.plan/v1","operation":"browser_managed_origin_removal",
        "browser":"chrome","profile":"Default","domain":"example.test",
        "origins":["https://example.test:8443"],"recoverable":false})
}

#[test]
fn framing_matches_external_wire_bytes_and_rejects_truncation_or_oversize() {
    let payload = br#"{"op":"hello","id":"r1"}"#;
    let mut wire = (payload.len() as u32).to_ne_bytes().to_vec();
    wire.extend_from_slice(payload);
    assert_eq!(
        read_frame(&mut Cursor::new(&wire)).unwrap().unwrap(),
        json!({"op":"hello","id":"r1"})
    );
    for length in [1, 3, wire.len() - 1] {
        assert!(read_frame(&mut Cursor::new(&wire[..length])).is_err());
    }
    assert!(read_frame(&mut Cursor::new(u32::MAX.to_ne_bytes())).is_err());
    assert!(read_frame(&mut Cursor::new(0u32.to_ne_bytes())).is_err());
    assert!(read_frame(&mut Cursor::new([])).unwrap().is_none());
    let mut out = Vec::new();
    write_frame(&mut out, &json!({"ok":true})).unwrap();
    assert_eq!(&out[4..], br#"{"ok":true}"#);
    assert_eq!(u32::from_ne_bytes(out[..4].try_into().unwrap()), 11);
    assert!(write_frame(&mut Vec::new(), &json!("x".repeat(OUTPUT_CAP))).is_err());
}

#[test]
fn protocol_has_no_path_delete_command_or_unbounded_selection_endpoint() {
    for value in [
        json!({"op":"delete","id":"r1","path":"/tmp"}),
        json!({"op":"scan","id":"r1","browser":"chrome","profile":"Default","path":"/"}),
        json!({"op":"complete","id":"r1","request_id":"1","status":"success","mode":"cache"}),
    ] {
        assert!(serde_json::from_value::<Request>(value).is_err());
    }
    for profile in ["../Default", "Profile ", "Profile -1", "Profile 1/../../"] {
        assert!(valid_selection("chrome", profile).is_err());
    }
    assert!(valid_selection("unknown", "Default").is_err());
    assert!(valid_selection("edge", "Profile 12").is_ok());
}

#[test]
fn mailbox_refuses_overwrite_and_false_completion_and_keeps_bounded_last_result() {
    let (_temp, root) = fixture();
    let status = mailbox_status(&root).unwrap();
    assert!(status["pending"].is_null());
    assert!(!root.exists());
    let request = publish_request(&root, plan()).unwrap();
    let id = request["request"]["requestId"].as_str().unwrap();
    assert!(publish_request(&root, plan()).is_err());
    assert!(
        complete_request(
            &root,
            "foreign",
            Completion::BrowserCompleted,
            Some(RemovalMode::Cache)
        )
        .is_err()
    );
    assert!(complete_request(&root, id, Completion::BrowserCompleted, None).is_err());
    let result = complete_request(
        &root,
        id,
        Completion::BrowserCompleted,
        Some(RemovalMode::Storage),
    )
    .unwrap();
    assert_eq!(result["status"], "browser_completed");
    assert!(result["reclaimedBytes"].is_null());
    assert_eq!(result["independentlyVerified"], false);
    assert_eq!(
        result["plan"]["origins"],
        json!(["https://example.test:8443"])
    );
    let status = mailbox_status(&root).unwrap();
    assert!(status["pending"].is_null());
    assert_eq!(status["lastResult"], result);
    assert!(
        complete_request(
            &root,
            id,
            Completion::BrowserCompleted,
            Some(RemovalMode::Storage)
        )
        .is_err()
    );
    let next = publish_request(&root, plan()).unwrap();
    assert_ne!(next["request"]["requestId"], id);
    complete_request(
        &root,
        next["request"]["requestId"].as_str().unwrap(),
        Completion::Rejected,
        None,
    )
    .unwrap();
    // Independent namespace oracle also includes the control lock hidden by Windows entries().
    let mut names: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec![".lock", "result.json"]);
}

#[test]
fn expired_requests_cannot_report_new_browser_success() {
    let (_temp, root) = fixture();
    let first = publish_request(&root, plan()).unwrap();
    let mut expired = first["request"].clone();
    expired["expiresAt"] = json!(now().unwrap() - 1);
    Directory::open(&root, false)
        .unwrap()
        .write_json("pending.json", &expired, INPUT_CAP)
        .unwrap();
    assert!(
        complete_request(
            &root,
            expired["requestId"].as_str().unwrap(),
            Completion::BrowserCompleted,
            Some(RemovalMode::Cache)
        )
        .is_err()
    );
    assert!(publish_request(&root, plan()).is_ok());
}

#[test]
fn bundles_are_embedded_reproducible_and_do_not_overwrite_user_files() {
    let (_temp, root) = fixture();
    let exported = export_bundle(&root).unwrap();
    assert_eq!(exported["extensionInstalled"], false);
    assert_eq!(exported["hostRegistered"], false);
    let directory = Directory::open(&root, false).unwrap();
    let extension = directory.child("extension").unwrap();
    let manifest = read_json(&extension, "manifest.json").unwrap().unwrap();
    assert_eq!(
        manifest["permissions"],
        json!(["browsingData", "nativeMessaging"])
    );
    assert!(manifest.get("host_permissions").is_none());
    assert_eq!(
        read_json(&directory, "org.sweepx.browser_bridge.json")
            .unwrap()
            .unwrap()["allowed_origins"],
        json!([ORIGIN])
    );
    assert_eq!(
        hash_file(&root.join(host_filename())).unwrap(),
        hash_file(&std::env::current_exe().unwrap()).unwrap()
    );
    std::fs::write(root.join("user-note"), "keep").unwrap();
    assert!(export_bundle(&root).is_err());
    assert_eq!(
        std::fs::read_to_string(root.join("user-note")).unwrap(),
        "keep"
    );
}

#[cfg(unix)]
#[test]
fn mailbox_and_export_refuse_symlinked_ancestors_without_touching_targets() {
    use std::os::unix::fs::symlink;
    let (_temp, root) = fixture();
    std::fs::create_dir(&root).unwrap();
    let linked = root.with_file_name("linked");
    symlink(&root, &linked).unwrap();
    assert!(publish_request(&linked, plan()).is_err());
    assert!(!root.join("pending.json").exists());
    assert!(export_bundle(&linked.join("bundle")).is_err());
    assert!(!root.join("bundle").exists());
}

#[test]
fn inventory_pages_preserve_cli_accounting_without_paths_or_false_zeroes() {
    use sweepx_core::browser_storage::{OriginUsage, SiteStorageReport};
    let analysis = BrowserStorageAnalysis {
        complete: false,
        issues: vec!["fixture_partial".into()],
        profiles: vec![SiteStorageReport {
            browser: "chrome".into(),
            profile: "Chrome / Default".into(),
            profile_name: "Default".into(),
            subsystem: "indexeddb".into(),
            subsystem_path: "/display/only".into(),
            subsystem_bytes: None,
            size_complete: false,
            fully_attributed: false,
            unattributed_bytes: None,
            snapshot_consistency: "non_atomic",
            origins: (0..45)
                .map(|i| OriginUsage {
                    storage_key: format!("https://example{i}.test"),
                    domain: format!("example{i}.test"),
                    bytes: Some("7".into()),
                    complete: true,
                    directory_count: 1,
                    directories: vec!["/never/authority".into()],
                    bucket_id: None,
                    bucket_name: None,
                })
                .collect(),
            issues: vec![],
        }],
    };
    let expected = crate::site_storage_command::render_json(&analysis, None);
    let mut bytes = Vec::new();
    stream_inventory(&mut bytes, "r1", &analysis).unwrap();
    let mut cursor = Cursor::new(bytes);
    let mut domains = Vec::new();
    let mut origins = Vec::new();
    let mut categories = Vec::new();
    while let Some(frame) = read_frame(&mut cursor).unwrap() {
        match frame["collection"].as_str() {
            Some("domains") => domains.extend(frame["rows"].as_array().unwrap().clone()),
            Some("origins") => origins.extend(frame["rows"].as_array().unwrap().clone()),
            Some("categories") => categories.extend(frame["rows"].as_array().unwrap().clone()),
            _ => (),
        }
        if let Some(rows) = frame["rows"].as_array() {
            assert!(rows.len() <= 20);
        }
    }
    assert_eq!(domains, *expected["domains"].as_array().unwrap());
    assert_eq!(origins.len(), 45);
    assert!(origins.iter().all(|r| r.get("directories").is_none()));
    assert!(categories[0]["subsystemBytes"].is_null());
    assert!(categories[0]["unattributedBytes"].is_null());
    assert!(categories[0].get("subsystemPath").is_none());
}
#[test]
fn pending_diagnostics_distinguish_expiry_selection_and_absence_without_exposing_a_plan() {
    let pending = json!({"expiresAt":200,"plan":{"browser":"edge","profile":"Default"}});
    for (value, browser, profile, at, expected) in [
        (Value::Null, "edge", "Default", 100, "none"),
        (pending.clone(), "edge", "Default", 200, "expired"),
        (
            pending.clone(),
            "chrome",
            "Default",
            100,
            "different_selection",
        ),
        (
            pending.clone(),
            "edge",
            "Profile 1",
            100,
            "different_selection",
        ),
        (
            json!({"expiresAt":"invalid"}),
            "edge",
            "Default",
            100,
            "expired",
        ),
    ] {
        let response = pending_response(&value, "r1", browser, profile, at);
        assert_eq!(response["state"], expected);
        assert!(response["request"].is_null());
    }
    let ready = pending_response(&pending, "r2", "edge", "Default", 199);
    assert_eq!(ready["state"], "ready");
    assert_eq!(ready["request"], pending);
}
